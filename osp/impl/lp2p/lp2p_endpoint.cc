// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/impl/lp2p/lp2p_endpoint.h"

#include <algorithm>
#include <utility>

#include "util/osp_logging.h"

namespace openscreen::osp {

namespace {

template <typename T>
using DecodeFunction = msgs::CborResult (*)(const uint8_t*, size_t, T&);

// Decodes a message, returning the number of bytes it took.
template <typename T>
ErrorOr<size_t> Decode(const uint8_t* buffer,
                       size_t buffer_size,
                       DecodeFunction<T> decode,
                       T& message,
                       const char* name) {
  const msgs::CborResult result = decode(buffer, buffer_size, message);
  if (result == msgs::kParserEOF) {
    return Error::Code::kCborIncompleteMessage;
  }
  if (result < 0) {
    OSP_LOG_WARN << "failed to parse " << name << ": " << result;
    return Error::Code::kParseError;
  }
  return static_cast<size_t>(result);
}

}  // namespace

Lp2pEndpoint::Lp2pEndpoint(ProtocolConnectionEndpoint& endpoint,
                           TaskRunner& task_runner,
                           bool is_quic_client,
                           ConnectionFactory connection_factory)
    : endpoint_(endpoint),
      task_runner_(task_runner),
      is_quic_client_(is_quic_client),
      connection_factory_(std::move(connection_factory)) {
  MessageDemuxer& demuxer = endpoint_->GetMessageDemuxer();
  open_request_watch_ = demuxer.SetDefaultMessageTypeWatch(
      msgs::Type::kDataChannelOpenRequest, this);
  open_response_watch_ = demuxer.SetDefaultMessageTypeWatch(
      msgs::Type::kDataChannelOpenResponse, this);
  data_frame_watch_ =
      demuxer.SetDefaultMessageTypeWatch(msgs::Type::kDataFrame, this);
}

Lp2pEndpoint::~Lp2pEndpoint() {
  for (auto& entry : connections_) {
    entry.second->OnEndpointGone();
  }
}

void Lp2pEndpoint::OnIncomingStream(
    std::unique_ptr<ProtocolConnection> stream) {
  stream->SetObserver(this);
  incoming_streams_.push_back(std::move(stream));
}

void Lp2pEndpoint::AddConnection(Lp2pConnection& connection) {
  connections_[connection.instance_id()] = &connection;
}

void Lp2pEndpoint::RemoveConnection(Lp2pConnection& connection) {
  auto entry = connections_.find(connection.instance_id());
  if (entry != connections_.end() && entry->second == &connection) {
    connections_.erase(entry);
  }
}

ErrorOr<size_t> Lp2pEndpoint::OnStreamMessage(uint64_t instance_id,
                                              uint64_t stream_id,
                                              msgs::Type message_type,
                                              const uint8_t* buffer,
                                              size_t buffer_size,
                                              Clock::time_point now) {
  switch (message_type) {
    case msgs::Type::kDataChannelOpenRequest:
      return OnOpenRequest(instance_id, stream_id, buffer, buffer_size);

    case msgs::Type::kDataChannelOpenResponse: {
      msgs::DataChannelOpenResponse response;
      ErrorOr<size_t> result =
          Decode(buffer, buffer_size, &msgs::DecodeDataChannelOpenResponse,
                 response, "data-channel-open-response");
      if (result.is_value()) {
        if (Lp2pConnection* connection = FindConnection(instance_id)) {
          connection->OnOpenResponse(stream_id, response);
        }
      }
      return result;
    }

    case msgs::Type::kDataFrame: {
      msgs::DataFrame frame;
      ErrorOr<size_t> result = Decode(
          buffer, buffer_size, &msgs::DecodeDataFrame, frame, "data-frame");
      if (result.is_value()) {
        if (Lp2pConnection* connection = FindConnection(instance_id)) {
          connection->OnDataFrame(stream_id, frame);
        } else {
          OSP_LOG_WARN << "dropping data-frame from instance " << instance_id
                       << " without a data channel";
        }
      }
      return result;
    }

    default:
      OSP_NOTREACHED();
  }
}

void Lp2pEndpoint::OnConnectionClosed(const ProtocolConnection& stream) {
  incoming_streams_.erase(
      std::remove_if(incoming_streams_.begin(), incoming_streams_.end(),
                     [&stream](const std::unique_ptr<ProtocolConnection>& s) {
                       return s.get() == &stream;
                     }),
      incoming_streams_.end());
}

ErrorOr<size_t> Lp2pEndpoint::OnOpenRequest(uint64_t instance_id,
                                            uint64_t stream_id,
                                            const uint8_t* buffer,
                                            size_t buffer_size) {
  msgs::DataChannelOpenRequest request;
  ErrorOr<size_t> result =
      Decode(buffer, buffer_size, &msgs::DecodeDataChannelOpenRequest, request,
             "data-channel-open-request");
  if (result.is_error()) {
    return result;
  }

  std::unique_ptr<ProtocolConnection> stream =
      TakeIncomingStream(instance_id, stream_id);
  if (!stream) {
    // The request did not open the stream it arrived on, e.g. it followed
    // another message on a stream this side opened.
    OSP_LOG_WARN << "ignoring data-channel-open-request on stream " << stream_id
                 << " from instance " << instance_id
                 << " that is not a new incoming stream";
    return result;
  }

  Lp2pConnection* connection = FindConnection(instance_id);
  if (!connection && connection_factory_) {
    connection = connection_factory_(instance_id);
  }
  if (!connection) {
    OSP_LOG_WARN << "rejecting data channel " << request.channel_id
                 << " from instance " << instance_id << " without a connection";
    stream->WriteMessage(
        msgs::DataChannelOpenResponse{
            .request_id = request.request_id,
            .result = msgs::DataChannelOpenResponse_result::kPermanentError},
        &msgs::EncodeDataChannelOpenResponse);
    DestroyStreamLater(std::move(stream));
    return result;
  }
  connection->OnOpenRequest(request, std::move(stream));
  return result;
}

void Lp2pEndpoint::DestroyStreamLater(
    std::unique_ptr<ProtocolConnection> stream) {
  if (!stream) {
    return;
  }
  stream->SetObserver(nullptr);
  task_runner_->PostTask([stream = std::move(stream)] {});
}

Lp2pConnection* Lp2pEndpoint::FindConnection(uint64_t instance_id) {
  auto entry = connections_.find(instance_id);
  return entry == connections_.end() ? nullptr : entry->second.get();
}

std::unique_ptr<ProtocolConnection> Lp2pEndpoint::TakeIncomingStream(
    uint64_t instance_id,
    uint64_t stream_id) {
  auto entry = std::find_if(
      incoming_streams_.begin(), incoming_streams_.end(),
      [instance_id, stream_id](const std::unique_ptr<ProtocolConnection>& s) {
        return s->GetInstanceID() == instance_id && s->GetID() == stream_id;
      });
  if (entry == incoming_streams_.end()) {
    return nullptr;
  }
  std::unique_ptr<ProtocolConnection> stream = std::move(*entry);
  incoming_streams_.erase(entry);
  stream->SetObserver(nullptr);
  return stream;
}

}  // namespace openscreen::osp

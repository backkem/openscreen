// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/public/lp2p/lp2p_connection.h"

#include <set>
#include <utility>

#include "osp/impl/lp2p/lp2p_endpoint.h"
#include "util/osp_logging.h"

namespace openscreen::osp {

Lp2pConnection::Delegate::Delegate() = default;
Lp2pConnection::Delegate::~Delegate() = default;

Lp2pConnection::Lp2pConnection(Lp2pEndpoint& endpoint,
                               uint64_t instance_id,
                               std::string instance_name)
    : endpoint_(&endpoint),
      instance_id_(instance_id),
      instance_name_(std::move(instance_name)) {
  endpoint_->AddConnection(*this);
}

Lp2pConnection::~Lp2pConnection() {
  if (endpoint_) {
    endpoint_->RemoveConnection(*this);
  }
  // Channels may outlive the connection; they close.
  std::map<uint64_t, raw_ptr<Lp2pDataChannel>> channels = std::move(channels_);
  for (auto& entry : channels) {
    entry.second->OnConnectionGone();
  }
}

ErrorOr<std::unique_ptr<Lp2pDataChannel>> Lp2pConnection::CreateDataChannel(
    const Lp2pDataChannelInit& init,
    Lp2pDataChannel::Delegate* delegate) {
  if (!endpoint_) {
    return Error(Error::Code::kNoActiveConnection);
  }

  uint64_t id = 0;
  if (init.id) {
    if (*init.id > kMaxLp2pDataChannelId) {
      return Error(Error::Code::kParameterOutOfRange,
                   "channel-id must be at most 65534");
    }
    id = *init.id;
  } else {
    // The lowest ID that no channel of this connection uses.
    std::set<uint64_t> used_ids;
    for (const auto& entry : channels_) {
      used_ids.insert(entry.second->id());
    }
    while (used_ids.count(id)) {
      ++id;
    }
    if (id > kMaxLp2pDataChannelId) {
      return Error(Error::Code::kParameterOutOfRange, "no free channel-id");
    }
  }

  std::unique_ptr<ProtocolConnection> stream =
      endpoint_->endpoint().CreateBidirectionalProtocolConnection(instance_id_);
  if (!stream) {
    return Error(Error::Code::kNoActiveConnection);
  }

  const msgs::DataChannelOpenRequest request = {
      .request_id =
          endpoint_->endpoint().GetInstanceRequestIds().GetNextRequestId(
              instance_id_),
      .channel_id = id,
      .label = init.label,
      .protocol = init.protocol};
  const Error write_error =
      stream->WriteMessage(request, &msgs::EncodeDataChannelOpenRequest);
  if (!write_error.ok()) {
    return write_error;
  }

  auto channel = std::unique_ptr<Lp2pDataChannel>(new Lp2pDataChannel(
      *this, id, init.label, init.protocol, std::move(stream),
      Lp2pDataChannel::State::kConnecting));
  channel->request_id_ = request.request_id;
  channel->SetDelegate(delegate);
  channels_[channel->stream_id_] = channel.get();
  return channel;
}

void Lp2pConnection::OnOpenRequest(const msgs::DataChannelOpenRequest& request,
                                   std::unique_ptr<ProtocolConnection> stream) {
  msgs::DataChannelOpenResponse response = {
      .request_id = request.request_id,
      .result = msgs::DataChannelOpenResponse_result::kSuccess};
  if (request.channel_id > kMaxLp2pDataChannelId || !delegate_) {
    OSP_LOG_WARN << "rejecting data channel " << request.channel_id
                 << " from instance " << instance_id_;
    response.result = msgs::DataChannelOpenResponse_result::kPermanentError;
  }
  stream->WriteMessage(response, &msgs::EncodeDataChannelOpenResponse);
  if (response.result != msgs::DataChannelOpenResponse_result::kSuccess) {
    DestroyStreamLater(std::move(stream));
    return;
  }

  auto channel = std::unique_ptr<Lp2pDataChannel>(new Lp2pDataChannel(
      *this, request.channel_id, request.label, request.protocol,
      std::move(stream), Lp2pDataChannel::State::kOpen));
  channels_[channel->stream_id_] = channel.get();
  OSP_VLOG << "data channel " << channel->id() << " (" << channel->label()
           << ") opened by instance " << instance_id_;
  delegate_->OnDataChannel(std::move(channel));
}

void Lp2pConnection::OnOpenResponse(
    uint64_t stream_id,
    const msgs::DataChannelOpenResponse& response) {
  auto entry = channels_.find(stream_id);
  if (entry == channels_.end()) {
    OSP_LOG_WARN << "ignoring data-channel-open-response on stream "
                 << stream_id << " without a data channel";
    return;
  }
  entry->second->OnOpenResponse(
      response.request_id,
      response.result == msgs::DataChannelOpenResponse_result::kSuccess);
}

void Lp2pConnection::OnDataFrame(uint64_t stream_id,
                                 const msgs::DataFrame& frame) {
  auto entry = channels_.find(stream_id);
  if (entry == channels_.end()) {
    OSP_LOG_WARN << "dropping data-frame on stream " << stream_id
                 << " without a data channel";
    return;
  }
  entry->second->OnDataFrame(frame.encoding_id, frame.payload);
}

void Lp2pConnection::OnEndpointGone() {
  endpoint_ = nullptr;
}

void Lp2pConnection::RemoveChannel(uint64_t stream_id) {
  channels_.erase(stream_id);
}

void Lp2pConnection::DestroyStreamLater(
    std::unique_ptr<ProtocolConnection> stream) {
  if (endpoint_) {
    endpoint_->DestroyStreamLater(std::move(stream));
  }
}

}  // namespace openscreen::osp

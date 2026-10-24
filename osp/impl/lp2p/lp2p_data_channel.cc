// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/public/lp2p/lp2p_data_channel.h"

#include <utility>

#include "osp/public/lp2p/lp2p_connection.h"
#include "util/osp_logging.h"

namespace openscreen::osp {

Lp2pDataChannel::Delegate::Delegate() = default;
Lp2pDataChannel::Delegate::~Delegate() = default;

Lp2pDataChannel::Lp2pDataChannel(Lp2pConnection& connection,
                                 uint64_t id,
                                 std::string label,
                                 std::string protocol,
                                 std::unique_ptr<ProtocolConnection> stream,
                                 State state)
    : connection_(&connection),
      id_(id),
      label_(std::move(label)),
      protocol_(std::move(protocol)),
      stream_(std::move(stream)),
      stream_id_(stream_->GetID()),
      state_(state) {
  stream_->SetObserver(this);
}

Lp2pDataChannel::~Lp2pDataChannel() {
  if (connection_) {
    connection_->RemoveChannel(stream_id_);
    connection_->DestroyStreamLater(std::move(stream_));
  }
}

Error Lp2pDataChannel::Send(std::string_view text) {
  return Send(
      ByteView(reinterpret_cast<const uint8_t*>(text.data()), text.size()),
      Lp2pDataEncoding::kString);
}

Error Lp2pDataChannel::Send(ByteView payload, Lp2pDataEncoding encoding) {
  if (state_ != State::kOpen || !stream_) {
    return Error::Code::kInvalidConnectionState;
  }
  msgs::DataFrame frame;
  frame.encoding_id = static_cast<uint64_t>(encoding);
  frame.payload.assign(payload.begin(), payload.end());
  return stream_->WriteMessage(frame, &msgs::EncodeDataFrame);
}

void Lp2pDataChannel::Close() {
  SetClosed(/*notify=*/false);
}

void Lp2pDataChannel::OnConnectionClosed(const ProtocolConnection& connection) {
  SetClosed(/*notify=*/true);
}

void Lp2pDataChannel::OnOpenResponse(uint64_t request_id, bool success) {
  if (state_ != State::kConnecting || request_id != request_id_) {
    OSP_LOG_WARN << "unexpected data-channel-open-response for data channel "
                 << id_ << " (request-id " << request_id << ")";
    return;
  }
  if (success) {
    SetOpen();
  } else {
    OSP_LOG_WARN << "data channel " << id_ << " (" << label_
                 << ") was rejected";
    SetClosed(/*notify=*/true);
  }
}

void Lp2pDataChannel::OnDataFrame(uint64_t encoding_id, ByteView payload) {
  if (state_ != State::kOpen) {
    OSP_LOG_WARN << "dropping data-frame on data channel " << id_
                 << " that is not open";
    return;
  }
  if (encoding_id > static_cast<uint64_t>(Lp2pDataEncoding::kArrayBuffer)) {
    OSP_LOG_WARN << "dropping data-frame with unknown encoding-id "
                 << encoding_id;
    return;
  }
  if (delegate_) {
    delegate_->OnMessage(*this, static_cast<Lp2pDataEncoding>(encoding_id),
                         payload);
  }
}

void Lp2pDataChannel::OnConnectionGone() {
  connection_ = nullptr;
  SetClosed(/*notify=*/true);
}

void Lp2pDataChannel::SetOpen() {
  state_ = State::kOpen;
  if (delegate_) {
    delegate_->OnOpen(*this);
  }
}

void Lp2pDataChannel::SetClosed(bool notify) {
  if (state_ == State::kClosed) {
    return;
  }
  state_ = State::kClosed;
  if (connection_) {
    connection_->RemoveChannel(stream_id_);
    connection_->DestroyStreamLater(std::move(stream_));
  }
  stream_.reset();
  if (notify && delegate_) {
    delegate_->OnClose(*this);
  }
}

}  // namespace openscreen::osp

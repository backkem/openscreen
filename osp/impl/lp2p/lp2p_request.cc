// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/public/lp2p/lp2p_request.h"

#include <string>
#include <utility>

#include "osp/impl/lp2p/lp2p_endpoint.h"
#include "osp/public/protocol_connection_client.h"
#include "util/osp_logging.h"

namespace openscreen::osp {

Lp2pRequest::Delegate::Delegate() = default;
Lp2pRequest::Delegate::~Delegate() = default;

Lp2pRequest::Lp2pRequest(ProtocolConnectionClient& client,
                         TaskRunner& task_runner)
    : client_(client),
      // Data channels from peers are only accepted on connections this side
      // made.
      endpoint_(std::make_unique<Lp2pEndpoint>(client,
                                               task_runner,
                                               /*is_quic_client=*/true,
                                               nullptr)) {}

Lp2pRequest::~Lp2pRequest() = default;

Error Lp2pRequest::Start(std::string_view instance_name, Delegate& delegate) {
  if (delegate_) {
    return Error(Error::Code::kOperationInProgress);
  }
  delegate_ = &delegate;
  // Failures are reported to `delegate` as well.
  client_->Connect(instance_name, connect_request_, this);
  return Error::None();
}

void Lp2pRequest::OnIncomingStream(std::unique_ptr<ProtocolConnection> stream) {
  endpoint_->OnIncomingStream(std::move(stream));
}

void Lp2pRequest::OnConnectSucceed(uint64_t request_id,
                                   std::string_view instance_name,
                                   uint64_t instance_id) {
  connect_request_.MarkComplete();
  Delegate* delegate = delegate_.get();
  delegate_ = nullptr;
  if (delegate) {
    delegate->OnConnection(std::make_unique<Lp2pConnection>(
        *endpoint_, instance_id, std::string(instance_name)));
  }
}

void Lp2pRequest::OnConnectFailed(uint64_t request_id,
                                  std::string_view instance_name) {
  connect_request_.MarkComplete();
  Delegate* delegate = delegate_.get();
  delegate_ = nullptr;
  if (delegate) {
    delegate->OnError(
        Error(Error::Code::kConnectionFailed,
              "failed to connect to " + std::string(instance_name)));
  }
}

}  // namespace openscreen::osp

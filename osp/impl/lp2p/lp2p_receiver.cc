// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/public/lp2p/lp2p_receiver.h"

#include <utility>

#include "osp/impl/lp2p/lp2p_endpoint.h"
#include "osp/public/protocol_connection_server.h"

namespace openscreen::osp {

Lp2pReceiver::Delegate::Delegate() = default;
Lp2pReceiver::Delegate::~Delegate() = default;

Lp2pReceiver::Lp2pReceiver(ProtocolConnectionServer& server,
                           TaskRunner& task_runner,
                           Delegate& delegate,
                           Lp2pConfig config)
    : delegate_(delegate),
      endpoint_(std::make_unique<Lp2pEndpoint>(server,
                                               task_runner,
                                               config,
                                               [this](uint64_t instance_id) {
                                                 return CreateConnection(
                                                     instance_id);
                                               })) {}

Lp2pReceiver::~Lp2pReceiver() = default;

void Lp2pReceiver::OnIncomingStream(
    std::unique_ptr<ProtocolConnection> stream) {
  endpoint_->OnIncomingStream(std::move(stream));
}

Lp2pConnection* Lp2pReceiver::CreateConnection(uint64_t instance_id) {
  auto connection =
      std::make_unique<Lp2pConnection>(*endpoint_, instance_id, std::string());
  Lp2pConnection* connection_ptr = connection.get();
  delegate_->OnConnection(std::move(connection));
  // The delegate may have dropped it, which removed it from `endpoint_`.
  return connection_ptr == endpoint_->FindConnection(instance_id)
             ? connection_ptr
             : nullptr;
}

}  // namespace openscreen::osp

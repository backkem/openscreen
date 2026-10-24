// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OSP_PUBLIC_LP2P_LP2P_REQUEST_H_
#define OSP_PUBLIC_LP2P_LP2P_REQUEST_H_

#include <cstdint>
#include <memory>
#include <string_view>

#include "osp/public/connect_request.h"
#include "osp/public/lp2p/lp2p_connection.h"
#include "osp/public/protocol_connection.h"
#include "platform/base/error.h"
#include "util/raw_ptr.h"
#include "util/raw_ref.h"

namespace openscreen {
class TaskRunner;
}  // namespace openscreen

namespace openscreen::osp {

class Lp2pEndpoint;
class ProtocolConnectionClient;

// The connecting side of the Local Peer-to-Peer API (`LP2PRequest`), on top of
// a `ProtocolConnectionClient` that observes a `ServiceListener`.
//
// The embedder advertises the `data-channels` agent capability in the
// client's `ServiceConfig::agent_info`, and forwards the incoming QUIC streams
// its `ProtocolConnectionServiceObserver` gets to `OnIncomingStream`.
//
// All methods must be called on `task_runner`. `client` must outlive this.
class Lp2pRequest final : public ConnectRequestCallback {
 public:
  class Delegate {
   public:
    Delegate();
    Delegate(const Delegate&) = delete;
    Delegate& operator=(const Delegate&) = delete;
    Delegate(Delegate&&) noexcept = delete;
    Delegate& operator=(Delegate&&) noexcept = delete;
    virtual ~Delegate();

    // The connection to the peer is established and authenticated.
    virtual void OnConnection(std::unique_ptr<Lp2pConnection> connection) = 0;
    virtual void OnError(const Error& error) = 0;
  };

  Lp2pRequest(ProtocolConnectionClient& client, TaskRunner& task_runner);
  Lp2pRequest(const Lp2pRequest&) = delete;
  Lp2pRequest& operator=(const Lp2pRequest&) = delete;
  Lp2pRequest(Lp2pRequest&&) noexcept = delete;
  Lp2pRequest& operator=(Lp2pRequest&&) noexcept = delete;
  ~Lp2pRequest() override;

  // Connects to the discovered agent `instance_name`, reporting the result to
  // `delegate`, possibly before this returns. One request at a time.
  Error Start(std::string_view instance_name, Delegate& delegate);

  // Takes a QUIC stream that a peer opened. Streams that do not turn out to
  // carry a data channel are kept until they close.
  void OnIncomingStream(std::unique_ptr<ProtocolConnection> stream);

  // ConnectRequestCallback overrides.
  void OnConnectSucceed(uint64_t request_id,
                        std::string_view instance_name,
                        uint64_t instance_id) override;
  void OnConnectFailed(uint64_t request_id,
                       std::string_view instance_name) override;

 private:
  const raw_ref<ProtocolConnectionClient> client_;
  std::unique_ptr<Lp2pEndpoint> endpoint_;
  ConnectRequest connect_request_;
  raw_ptr<Delegate> delegate_ = nullptr;
};

}  // namespace openscreen::osp

#endif  // OSP_PUBLIC_LP2P_LP2P_REQUEST_H_

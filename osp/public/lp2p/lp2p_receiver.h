// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OSP_PUBLIC_LP2P_LP2P_RECEIVER_H_
#define OSP_PUBLIC_LP2P_LP2P_RECEIVER_H_

#include <memory>

#include "osp/public/lp2p/lp2p_connection.h"
#include "osp/public/protocol_connection.h"
#include "util/raw_ref.h"

namespace openscreen {
class TaskRunner;
}  // namespace openscreen

namespace openscreen::osp {

class Lp2pEndpoint;
class ProtocolConnectionServer;

// The accepting side of the Local Peer-to-Peer API (`LP2PReceiver`), on top of
// a `ProtocolConnectionServer` that is advertised with a `ServicePublisher`.
//
// The embedder advertises the `data-channels` agent capability in the
// server's `ServiceConfig::agent_info`, and forwards the incoming QUIC streams
// its `ProtocolConnectionServiceObserver` gets to `OnIncomingStream`.
//
// The server does not report when a peer has authenticated, so a peer's
// `Lp2pConnection` is handed to the delegate when the peer opens its first
// data channel, right before that channel.
//
// All methods must be called on `task_runner`. `server` must outlive this.
class Lp2pReceiver final {
 public:
  class Delegate {
   public:
    Delegate();
    Delegate(const Delegate&) = delete;
    Delegate& operator=(const Delegate&) = delete;
    Delegate(Delegate&&) noexcept = delete;
    Delegate& operator=(Delegate&&) noexcept = delete;
    virtual ~Delegate();

    // A peer connected. The delegate should set the connection's delegate
    // and keep it; destroying it rejects the peer's data channels.
    virtual void OnConnection(std::unique_ptr<Lp2pConnection> connection) = 0;
  };

  Lp2pReceiver(ProtocolConnectionServer& server,
               TaskRunner& task_runner,
               Delegate& delegate,
               Lp2pConfig config = {});
  Lp2pReceiver(const Lp2pReceiver&) = delete;
  Lp2pReceiver& operator=(const Lp2pReceiver&) = delete;
  Lp2pReceiver(Lp2pReceiver&&) noexcept = delete;
  Lp2pReceiver& operator=(Lp2pReceiver&&) noexcept = delete;
  ~Lp2pReceiver();

  // Takes a QUIC stream that a peer opened. Streams that do not turn out to
  // carry a data channel are kept until they close.
  void OnIncomingStream(std::unique_ptr<ProtocolConnection> stream);

 private:
  Lp2pConnection* CreateConnection(uint64_t instance_id);

  const raw_ref<Delegate> delegate_;
  std::unique_ptr<Lp2pEndpoint> endpoint_;
};

}  // namespace openscreen::osp

#endif  // OSP_PUBLIC_LP2P_LP2P_RECEIVER_H_

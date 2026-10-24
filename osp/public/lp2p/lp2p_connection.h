// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OSP_PUBLIC_LP2P_LP2P_CONNECTION_H_
#define OSP_PUBLIC_LP2P_LP2P_CONNECTION_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "osp/msgs/osp_messages.h"
#include "osp/public/lp2p/lp2p_data_channel.h"
#include "osp/public/protocol_connection.h"
#include "platform/base/error.h"
#include "util/raw_ptr.h"

namespace openscreen::osp {

class Lp2pEndpoint;

// An authenticated Open Screen Protocol connection to a peer that data
// channels can be opened on, as the `LP2PConnection` interface of the Local
// Peer-to-Peer spec. Created by `Lp2pReceiver` and `Lp2pRequest`, which must
// outlive it.
//
// All methods must be called on the task runner of the `Lp2pReceiver` or
// `Lp2pRequest` that created it.
class Lp2pConnection final {
 public:
  class Delegate {
   public:
    Delegate();
    Delegate(const Delegate&) = delete;
    Delegate& operator=(const Delegate&) = delete;
    Delegate(Delegate&&) noexcept = delete;
    Delegate& operator=(Delegate&&) noexcept = delete;
    virtual ~Delegate();

    // The peer opened `channel`, which is open. The delegate should set the
    // channel's delegate; the channel closes if it is destroyed.
    virtual void OnDataChannel(std::unique_ptr<Lp2pDataChannel> channel) = 0;
  };

  Lp2pConnection(Lp2pEndpoint& endpoint,
                 uint64_t instance_id,
                 std::string instance_name);
  Lp2pConnection(const Lp2pConnection&) = delete;
  Lp2pConnection& operator=(const Lp2pConnection&) = delete;
  Lp2pConnection(Lp2pConnection&&) noexcept = delete;
  Lp2pConnection& operator=(Lp2pConnection&&) noexcept = delete;
  ~Lp2pConnection();

  uint64_t instance_id() const { return instance_id_; }
  // The peer's instance name, when known (the requesting side knows it).
  const std::string& instance_name() const { return instance_name_; }

  void SetDelegate(Delegate* delegate) { delegate_ = delegate; }

  // Opens a data channel by sending a `data-channel-open-request` on a new
  // QUIC stream. The channel starts in `kConnecting`; `delegate` learns when
  // the peer accepts or rejects it.
  //
  // Without `init.id`, the channel gets the lowest ID of the local parity
  // that no channel of this connection uses: even on the requester side (the
  // QUIC client), odd on the receiver side (the QUIC server). An explicit
  // `init.id` must be free and of the local parity. Channels the peer opens
  // are accepted whatever their ID's parity.
  ErrorOr<std::unique_ptr<Lp2pDataChannel>> CreateDataChannel(
      const Lp2pDataChannelInit& init,
      Lp2pDataChannel::Delegate* delegate);

 private:
  friend class Lp2pDataChannel;
  friend class Lp2pEndpoint;

  // Called by `endpoint_` for the messages on this connection's streams.
  void OnOpenRequest(const msgs::DataChannelOpenRequest& request,
                     std::unique_ptr<ProtocolConnection> stream);
  void OnOpenResponse(uint64_t stream_id,
                      const msgs::DataChannelOpenResponse& response);
  void OnDataFrame(uint64_t stream_id, const msgs::DataFrame& frame);
  void OnEndpointGone();

  // Called by `Lp2pDataChannel`.
  void RemoveChannel(uint64_t stream_id);
  // Destroys, and so finishes, `stream` from a fresh task: the demuxer may be
  // handling a message of the stream.
  void DestroyStreamLater(std::unique_ptr<ProtocolConnection> stream);

  raw_ptr<Lp2pEndpoint> endpoint_;
  const uint64_t instance_id_;
  const std::string instance_name_;
  // 0 on the requester side, which allocates even channel IDs; 1 on the
  // receiver side, which allocates odd ones.
  const uint64_t channel_id_parity_;
  raw_ptr<Delegate> delegate_ = nullptr;
  // The open and opening channels, by QUIC stream ID.
  std::map<uint64_t, raw_ptr<Lp2pDataChannel>> channels_;
};

}  // namespace openscreen::osp

#endif  // OSP_PUBLIC_LP2P_LP2P_CONNECTION_H_

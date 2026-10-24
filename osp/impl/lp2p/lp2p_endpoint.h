// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OSP_IMPL_LP2P_LP2P_ENDPOINT_H_
#define OSP_IMPL_LP2P_LP2P_ENDPOINT_H_

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <vector>

#include "osp/public/lp2p/lp2p_connection.h"
#include "osp/public/message_demuxer.h"
#include "osp/public/protocol_connection.h"
#include "osp/public/protocol_connection_endpoint.h"
#include "platform/api/task_runner.h"
#include "util/raw_ptr.h"
#include "util/raw_ref.h"

namespace openscreen::osp {

// The shared part of `Lp2pReceiver` and `Lp2pRequest`: it watches the data
// channel messages on a `ProtocolConnectionEndpoint` and routes them to the
// `Lp2pConnection` of the instance they come from, and it holds the QUIC
// streams that peers opened until a `data-channel-open-request` claims one.
class Lp2pEndpoint final : public MessageDemuxer::MessageCallback,
                           public ProtocolConnection::Observer {
 public:
  // Returns the connection for a peer that opens a data channel before it
  // has one, or nullptr to reject the channel.
  using ConnectionFactory = std::function<Lp2pConnection*(uint64_t)>;

  Lp2pEndpoint(ProtocolConnectionEndpoint& endpoint,
               TaskRunner& task_runner,
               Lp2pConfig config,
               ConnectionFactory connection_factory);
  Lp2pEndpoint(const Lp2pEndpoint&) = delete;
  Lp2pEndpoint& operator=(const Lp2pEndpoint&) = delete;
  Lp2pEndpoint(Lp2pEndpoint&&) noexcept = delete;
  Lp2pEndpoint& operator=(Lp2pEndpoint&&) noexcept = delete;
  ~Lp2pEndpoint() override;

  ProtocolConnectionEndpoint& endpoint() { return *endpoint_; }
  TaskRunner& task_runner() { return *task_runner_; }
  const Lp2pConfig& config() const { return config_; }

  void OnIncomingStream(std::unique_ptr<ProtocolConnection> stream);

  void AddConnection(Lp2pConnection& connection);
  void RemoveConnection(Lp2pConnection& connection);
  Lp2pConnection* FindConnection(uint64_t instance_id);

  // Destroys, and so finishes, `stream` from a fresh task. Streams must not be
  // closed while the demuxer handles one of their messages.
  void DestroyStreamLater(std::unique_ptr<ProtocolConnection> stream);

  // MessageDemuxer::MessageCallback overrides.
  ErrorOr<size_t> OnStreamMessage(uint64_t instance_id,
                                  uint64_t stream_id,
                                  msgs::Type message_type,
                                  const uint8_t* buffer,
                                  size_t buffer_size,
                                  Clock::time_point now) override;

  // ProtocolConnection::Observer overrides, for the held incoming streams.
  void OnConnectionClosed(const ProtocolConnection& stream) override;

 private:
  ErrorOr<size_t> OnOpenRequest(uint64_t instance_id,
                                uint64_t stream_id,
                                const uint8_t* buffer,
                                size_t buffer_size);
  std::unique_ptr<ProtocolConnection> TakeIncomingStream(uint64_t instance_id,
                                                         uint64_t stream_id);

  const raw_ref<ProtocolConnectionEndpoint> endpoint_;
  const raw_ref<TaskRunner> task_runner_;
  const Lp2pConfig config_;
  const ConnectionFactory connection_factory_;

  std::map<uint64_t, raw_ptr<Lp2pConnection>> connections_;
  // Streams opened by peers that no data channel has claimed yet.
  std::vector<std::unique_ptr<ProtocolConnection>> incoming_streams_;

  MessageDemuxer::MessageWatch open_request_watch_;
  MessageDemuxer::MessageWatch open_response_watch_;
  MessageDemuxer::MessageWatch data_frame_watch_;
};

}  // namespace openscreen::osp

#endif  // OSP_IMPL_LP2P_LP2P_ENDPOINT_H_

// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OSP_PUBLIC_LP2P_LP2P_DATA_CHANNEL_H_
#define OSP_PUBLIC_LP2P_LP2P_DATA_CHANNEL_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "osp/public/protocol_connection.h"
#include "platform/base/error.h"
#include "platform/base/span.h"
#include "util/raw_ptr.h"
#include "util/weak_ptr.h"

namespace openscreen::osp {

class Lp2pConnection;

// The `data-channel-encoding-id` of a `data-frame`, from the Local
// Peer-to-Peer data channel extension.
enum class Lp2pDataEncoding : uint64_t {
  kBlob = 0,
  kString = 1,
  kArrayBuffer = 2,
};

// The largest `channel-id` the data channel extension allows.
inline constexpr uint64_t kMaxLp2pDataChannelId = 65534;

// Parameters for `Lp2pConnection::CreateDataChannel`, a subset of the
// `LP2PDataChannelInit` dictionary.
struct Lp2pDataChannelInit {
  std::string label;
  std::string protocol;
  // The `channel-id`, at most `kMaxLp2pDataChannelId`. When unset, the lowest
  // ID not used by another channel of the connection is picked.
  std::optional<uint64_t> id;
};

// A bidirectional data channel of an `Lp2pConnection`, carried by one QUIC
// stream: the stream that the `data-channel-open-request` was sent on, which
// then carries the `data-channel-open-response` and `data-frame` messages in
// both directions.
//
// Created by `Lp2pConnection::CreateDataChannel` (starting in `kConnecting`)
// or handed to `Lp2pConnection::Delegate::OnDataChannel` (already `kOpen`).
// Destroying the channel, or calling `Close`, finishes its QUIC stream.
//
// All methods must be called on the task runner of the `Lp2pReceiver` or
// `Lp2pRequest` that created the connection.
class Lp2pDataChannel final : public ProtocolConnection::Observer {
 public:
  enum class State {
    kConnecting,
    kOpen,
    kClosed,
  };

  class Delegate {
   public:
    Delegate();
    Delegate(const Delegate&) = delete;
    Delegate& operator=(const Delegate&) = delete;
    Delegate(Delegate&&) noexcept = delete;
    Delegate& operator=(Delegate&&) noexcept = delete;
    virtual ~Delegate();

    // The peer accepted a channel created with `CreateDataChannel`.
    virtual void OnOpen(Lp2pDataChannel& channel) = 0;

    // A `data-frame` arrived on the open channel.
    virtual void OnMessage(Lp2pDataChannel& channel,
                           Lp2pDataEncoding encoding,
                           ByteView payload) = 0;

    // The channel closed: the peer rejected it, or its QUIC stream closed.
    // Not called for `Close`.
    virtual void OnClose(Lp2pDataChannel& channel) = 0;
  };

  Lp2pDataChannel(const Lp2pDataChannel&) = delete;
  Lp2pDataChannel& operator=(const Lp2pDataChannel&) = delete;
  Lp2pDataChannel(Lp2pDataChannel&&) noexcept = delete;
  Lp2pDataChannel& operator=(Lp2pDataChannel&&) noexcept = delete;
  ~Lp2pDataChannel() override;

  uint64_t id() const { return id_; }
  const std::string& label() const { return label_; }
  const std::string& protocol() const { return protocol_; }
  State state() const { return state_; }

  void SetDelegate(Delegate* delegate) { delegate_ = delegate; }

  // Sends `text` as a `data-frame` with the string encoding.
  Error Send(std::string_view text);

  // Sends `payload` as a `data-frame` with `encoding`.
  Error Send(ByteView payload, Lp2pDataEncoding encoding);

  // Closes the channel by finishing its QUIC stream.
  void Close();

  // ProtocolConnection::Observer overrides.
  void OnConnectionClosed(const ProtocolConnection& connection) override;

 private:
  friend class Lp2pConnection;

  Lp2pDataChannel(Lp2pConnection& connection,
                  uint64_t id,
                  std::string label,
                  std::string protocol,
                  std::unique_ptr<ProtocolConnection> stream,
                  State state);

  // Called by `connection_`.
  void OnOpenResponse(uint64_t request_id, bool success);
  void OnDataFrame(uint64_t encoding_id, ByteView payload);
  void OnConnectionGone();

  void SetOpen();
  void SetClosed(bool notify);

  raw_ptr<Lp2pConnection> connection_;
  const uint64_t id_;
  const std::string label_;
  const std::string protocol_;
  std::unique_ptr<ProtocolConnection> stream_;
  // The QUIC stream ID, which the connection routes messages by.
  const uint64_t stream_id_;
  State state_;
  // The request ID of the `data-channel-open-request` this side sent.
  uint64_t request_id_ = 0;
  raw_ptr<Delegate> delegate_ = nullptr;

  WeakPtrFactory<Lp2pDataChannel> weak_factory_{this};
};

}  // namespace openscreen::osp

#endif  // OSP_PUBLIC_LP2P_LP2P_DATA_CHANNEL_H_

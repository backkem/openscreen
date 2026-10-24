// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OSP_IMPL_QUIC_AGENT_AUTHENTICATOR_H_
#define OSP_IMPL_QUIC_AGENT_AUTHENTICATOR_H_

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "osp/msgs/osp_messages.h"
#include "osp/public/agent_certificate.h"
#include "osp/public/authentication_config.h"
#include "osp/public/message_demuxer.h"
#include "osp/public/protocol_connection.h"
#include "platform/api/task_runner.h"
#include "platform/api/time.h"
#include "platform/base/error.h"
#include "util/alarm.h"
#include "util/crypto/spake2.h"
#include "util/raw_ref.h"

namespace openscreen::osp {

// Runs the network.bs network phase on each QUIC connection, once the QUIC
// handshake is complete:
//  - metadata discovery: answers agent-info-request and sends one, and
//  - authentication: exchanges auth-capabilities and runs SPAKE2
//    ("Authentication with SPAKE2") with auth-spake2-handshake,
//    auth-spake2-confirmation and auth-status.
//
// One instance serves all connections of a QuicServiceBase; per-connection
// state is keyed by instance ID.
class AgentAuthenticator final : public MessageDemuxer::MessageCallback {
 public:
  class Delegate {
   public:
    virtual ~Delegate() = default;
    // Creates a new outgoing stream on the connection for `instance_id`.
    virtual std::unique_ptr<ProtocolConnection> CreateNetworkProtocolConnection(
        uint64_t instance_id) = 0;
    virtual void OnAuthenticationSucceeded(uint64_t instance_id) = 0;
    // The delegate must close the connection.
    virtual void OnAuthenticationFailed(uint64_t instance_id,
                                        const Error& error) = 0;
  };

  struct PeerInfo {
    // True if the local agent is the QUIC server (advertising agent).
    bool local_is_server = false;
    AgentFingerprint local_fingerprint;
    AgentFingerprint peer_fingerprint;
    // The `at` of the advertising agent (the local one when
    // `local_is_server`), used as the auth-initiation-token.
    std::string auth_token;
    // For logging.
    std::string peer_name;
  };

  // Returns true for messages that may be exchanged before authentication:
  // metadata discovery and authentication messages.
  static bool IsNetworkPhaseMessage(msgs::Type type);

  AgentAuthenticator(const AgentInfoConfig& agent_info,
                     const AuthenticationConfig& config,
                     MessageDemuxer& demuxer,
                     Delegate& delegate,
                     ClockNowFunctionPtr now_function,
                     TaskRunner& task_runner);
  AgentAuthenticator(const AgentAuthenticator&) = delete;
  AgentAuthenticator& operator=(const AgentAuthenticator&) = delete;
  ~AgentAuthenticator() override;

  // Starts the network phase for a connection whose QUIC handshake completed.
  void Start(uint64_t instance_id, PeerInfo peer);
  // Forgets a closed connection.
  void Remove(uint64_t instance_id);

  bool IsAuthenticated(uint64_t instance_id) const;
  // Returns the peer's (unverified before authentication) agent-info, if any.
  const msgs::AgentInfo* GetPeerAgentInfo(uint64_t instance_id) const;

  const AuthenticationConfig& config() const { return config_; }

  // MessageDemuxer::MessageCallback overrides.
  ErrorOr<size_t> OnStreamMessage(uint64_t instance_id,
                                  uint64_t connection_id,
                                  msgs::Type message_type,
                                  const uint8_t* buffer,
                                  size_t buffer_size,
                                  Clock::time_point now) override;

  // PSK helpers, per network.bs "Appendix B: PSK Encoding Schemes".
  //
  // Decodes a numeric PSK string: "Remove dashes and leading zeros from N."
  // Whitespace is ignored too. Returns an empty string if `psk` contains other
  // non-digit characters.
  static std::string CanonicalizePsk(std::string_view psk);
  // Encodes a PSK for display, in groups of 3 (fewer than 9 digits) or 4
  // digits separated by dashes.
  static std::string FormatPskForDisplay(std::string_view canonical_psk);
  // Returns a random PSK with `bits` bits of entropy (20 to 60).
  static std::string GeneratePsk(uint64_t bits);

 private:
  struct State {
    State();
    ~State();

    PeerInfo peer;
    std::unique_ptr<ProtocolConnection> sender;
    std::optional<msgs::AuthCapabilities> peer_capabilities;
    std::optional<msgs::AgentInfo> peer_agent_info;
    uint64_t agent_info_request_id = 0;

    // The canonical PSK once known.
    std::string psk;
    // Whether the local agent is SPAKE2 Alice (the initiator).
    bool is_alice = false;
    std::unique_ptr<Spake2> spake2;
    std::vector<uint8_t> peer_confirmation;  // Received before ready.
    bool sent_confirmation = false;
    bool authenticated = false;
    bool failed = false;
    // Fires `config_.timeout` after `Start` unless authentication completed.
    std::unique_ptr<Alarm> timeout_alarm;
  };

  bool IsPresenter(const State& state) const;
  // Returns the PSK to use, presenting a generated one if needed.
  std::string ObtainPsk(State& state, bool presenter);
  ErrorOr<std::unique_ptr<Spake2>> CreateSpake2(const State& state,
                                                bool is_alice,
                                                const std::string& psk) const;

  void MaybeInitiate(uint64_t instance_id, State& state);
  void HandleHandshake(uint64_t instance_id,
                       State& state,
                       const msgs::AuthSpake2Handshake& message);
  void HandleConfirmation(uint64_t instance_id,
                          State& state,
                          const std::vector<uint8_t>& confirmation);
  void MaybeSendConfirmation(State& state);
  void MaybeVerifyPeerConfirmation(uint64_t instance_id, State& state);
  void OnTimeout(uint64_t instance_id);
  void Fail(uint64_t instance_id,
            State& state,
            msgs::AuthStatusResult result,
            const Error& error);

  void SendHandshake(State& state, msgs::AuthSpake2PskStatus status);
  template <typename T>
  void Send(State& state, const T& message, MessageEncodingFunction<T> encoder);

  const AgentInfoConfig agent_info_;
  const AuthenticationConfig config_;
  const raw_ref<MessageDemuxer> demuxer_;
  const raw_ref<Delegate> delegate_;
  const ClockNowFunctionPtr now_function_;
  const raw_ref<TaskRunner> task_runner_;
  uint64_t next_request_id_ = 1;
  std::map<uint64_t, std::unique_ptr<State>> states_;
  std::vector<MessageDemuxer::MessageWatch> watches_;
};

}  // namespace openscreen::osp

#endif  // OSP_IMPL_QUIC_AGENT_AUTHENTICATOR_H_

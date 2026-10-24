// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/impl/quic/agent_authenticator.h"

#include <algorithm>
#include <utility>

#include "util/crypto/random_bytes.h"
#include "util/osp_logging.h"

namespace openscreen::osp {

namespace {

// Message types that may be exchanged before authentication.
constexpr msgs::Type kNetworkPhaseTypes[] = {
    msgs::Type::kAgentInfoRequest,       msgs::Type::kAgentInfoResponse,
    msgs::Type::kAgentStatusRequest,     msgs::Type::kAgentStatusResponse,
    msgs::Type::kAgentInfoEvent,         msgs::Type::kAuthCapabilities,
    msgs::Type::kAuthSpake2Confirmation, msgs::Type::kAuthStatus,
    msgs::Type::kAuthSpake2Handshake,
};

// Message types handled by AgentAuthenticator.
constexpr msgs::Type kHandledTypes[] = {
    msgs::Type::kAgentInfoRequest,       msgs::Type::kAgentInfoResponse,
    msgs::Type::kAuthCapabilities,       msgs::Type::kAuthSpake2Handshake,
    msgs::Type::kAuthSpake2Confirmation, msgs::Type::kAuthStatus,
};

constexpr uint64_t kMinPskBits = 20;
constexpr uint64_t kMaxPskBits = 60;

std::vector<uint8_t> ToBytes(std::string_view s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

// Decodes `buffer` with `decoder`, mapping errors as the demuxer expects.
template <typename T>
ErrorOr<size_t> Decode(const uint8_t* buffer,
                       size_t buffer_size,
                       T& message,
                       msgs::CborResult (*decoder)(const uint8_t*, size_t, T&),
                       const char* name) {
  const msgs::CborResult result = decoder(buffer, buffer_size, message);
  if (result < 0) {
    if (result == msgs::kParserEOF) {
      return Error::Code::kCborIncompleteMessage;
    }
    OSP_LOG_WARN << name << " parse error: " << result;
    return Error::Code::kParseError;
  }
  return static_cast<size_t>(result);
}

}  // namespace

AgentAuthenticator::State::State() = default;
AgentAuthenticator::State::~State() = default;

// static
bool AgentAuthenticator::IsNetworkPhaseMessage(msgs::Type type) {
  return std::find(std::begin(kNetworkPhaseTypes), std::end(kNetworkPhaseTypes),
                   type) != std::end(kNetworkPhaseTypes);
}

AgentAuthenticator::AgentAuthenticator(const AgentInfoConfig& agent_info,
                                       const AuthenticationConfig& config,
                                       MessageDemuxer& demuxer,
                                       Delegate& delegate,
                                       ClockNowFunctionPtr now_function,
                                       TaskRunner& task_runner)
    : agent_info_(agent_info),
      config_(config),
      demuxer_(demuxer),
      delegate_(delegate),
      now_function_(now_function),
      task_runner_(task_runner) {
  for (msgs::Type type : kHandledTypes) {
    watches_.push_back(demuxer.SetDefaultMessageTypeWatch(type, this));
  }
}

AgentAuthenticator::~AgentAuthenticator() = default;

void AgentAuthenticator::Start(uint64_t instance_id, PeerInfo peer) {
  auto state = std::make_unique<State>();
  state->peer = std::move(peer);
  state->sender = delegate_->CreateNetworkProtocolConnection(instance_id);
  if (!state->sender) {
    OSP_LOG_WARN << "Cannot open a stream to " << state->peer.peer_name;
    return;
  }
  State& s = *state;
  states_[instance_id] = std::move(state);

  if (config_.enabled) {
    s.timeout_alarm = std::make_unique<Alarm>(now_function_, *task_runner_);
    s.timeout_alarm->ScheduleFromNow(
        [this, instance_id] { OnTimeout(instance_id); }, config_.timeout);
  }

  OSP_LOG_INFO << "Network phase with " << s.peer.peer_name << " (instance "
               << instance_id << ", local "
               << (s.peer.local_is_server ? "server" : "client")
               << "): local fp=" << s.peer.local_fingerprint
               << " peer fp=" << s.peer.peer_fingerprint;

  // network.bs: "Prior to authentication, agents exchange auth-capabilities
  // messages".
  msgs::AuthCapabilities capabilities;
  capabilities.psk_ease_of_input = config_.psk_ease_of_input;
  capabilities.psk_input_methods = {msgs::PskInputMethod::kNumeric};
  capabilities.psk_min_bits_of_entropy = config_.psk_min_bits_of_entropy;
  Send(s, capabilities, &msgs::EncodeAuthCapabilities);

  msgs::AgentInfoRequest info_request;
  info_request.request_id = next_request_id_++;
  s.agent_info_request_id = info_request.request_id;
  Send(s, info_request, &msgs::EncodeAgentInfoRequest);

  // Process messages the peer sent before the network phase started here.
  demuxer_->RetryBufferedMessages(instance_id);
  if (states_.find(instance_id) == states_.end()) {
    return;
  }

  if (!config_.enabled) {
    OSP_LOG_WARN << "Authentication disabled (NON-SPEC): treating "
                 << s.peer.peer_name << " as authenticated";
    s.authenticated = true;
    delegate_->OnAuthenticationSucceeded(instance_id);
  }
}

void AgentAuthenticator::Remove(uint64_t instance_id) {
  states_.erase(instance_id);
}

bool AgentAuthenticator::IsAuthenticated(uint64_t instance_id) const {
  auto it = states_.find(instance_id);
  return it != states_.end() && it->second->authenticated;
}

const msgs::AgentInfo* AgentAuthenticator::GetPeerAgentInfo(
    uint64_t instance_id) const {
  auto it = states_.find(instance_id);
  if (it == states_.end() || !it->second->peer_agent_info) {
    return nullptr;
  }
  return &*it->second->peer_agent_info;
}

ErrorOr<size_t> AgentAuthenticator::OnStreamMessage(uint64_t instance_id,
                                                    uint64_t connection_id,
                                                    msgs::Type message_type,
                                                    const uint8_t* buffer,
                                                    size_t buffer_size,
                                                    Clock::time_point now) {
  auto it = states_.find(instance_id);
  if (it == states_.end()) {
    // The peer may send before the local side has started the network phase
    // for this connection. Keep the message buffered; `Start` retries it.
    return Error::Code::kCborIncompleteMessage;
  }
  State* state = it->second.get();

  switch (message_type) {
    case msgs::Type::kAgentInfoRequest: {
      msgs::AgentInfoRequest request;
      auto result = Decode(buffer, buffer_size, request,
                           &msgs::DecodeAgentInfoRequest, "agent-info-request");
      if (result && state) {
        msgs::AgentInfoResponse response;
        response.request_id = request.request_id;
        response.agent_info.display_name = agent_info_.display_name;
        response.agent_info.model_name = agent_info_.model_name;
        response.agent_info.capabilities = agent_info_.capabilities;
        response.agent_info.state_token = "0";
        response.agent_info.locales = agent_info_.locales;
        Send(*state, response, &msgs::EncodeAgentInfoResponse);
      }
      return result;
    }

    case msgs::Type::kAgentInfoResponse: {
      msgs::AgentInfoResponse response;
      auto result =
          Decode(buffer, buffer_size, response, &msgs::DecodeAgentInfoResponse,
                 "agent-info-response");
      if (result && state &&
          response.request_id == state->agent_info_request_id) {
        OSP_LOG_INFO << "agent-info from " << state->peer.peer_name
                     << (state->authenticated ? "" : " (unverified)")
                     << ": display-name=\"" << response.agent_info.display_name
                     << "\" model-name=\"" << response.agent_info.model_name
                     << "\"";
        state->peer_agent_info = std::move(response.agent_info);
      }
      return result;
    }

    case msgs::Type::kAuthCapabilities: {
      msgs::AuthCapabilities capabilities;
      auto result = Decode(buffer, buffer_size, capabilities,
                           &msgs::DecodeAuthCapabilities, "auth-capabilities");
      if (result && state && !state->peer_capabilities) {
        OSP_LOG_INFO << "auth-capabilities from " << state->peer.peer_name
                     << ": psk-ease-of-input=" << capabilities.psk_ease_of_input
                     << " psk-min-bits-of-entropy="
                     << capabilities.psk_min_bits_of_entropy;
        state->peer_capabilities = std::move(capabilities);
        MaybeInitiate(instance_id, *state);
      }
      return result;
    }

    case msgs::Type::kAuthSpake2Handshake: {
      msgs::AuthSpake2Handshake handshake;
      auto result =
          Decode(buffer, buffer_size, handshake,
                 &msgs::DecodeAuthSpake2Handshake, "auth-spake2-handshake");
      if (result && state) {
        HandleHandshake(instance_id, *state, handshake);
      }
      return result;
    }

    case msgs::Type::kAuthSpake2Confirmation: {
      msgs::AuthSpake2Confirmation confirmation;
      auto result = Decode(buffer, buffer_size, confirmation,
                           &msgs::DecodeAuthSpake2Confirmation,
                           "auth-spake2-confirmation");
      if (result && state) {
        HandleConfirmation(instance_id, *state,
                           confirmation.confirmation_value);
      }
      return result;
    }

    case msgs::Type::kAuthStatus: {
      msgs::AuthStatus status;
      auto result = Decode(buffer, buffer_size, status, &msgs::DecodeAuthStatus,
                           "auth-status");
      if (result && state) {
        OSP_LOG_INFO << "auth-status from " << state->peer.peer_name << ": "
                     << status.result;
        // network.bs: "Any value of result other than authenticated means
        // that authentication failed, and the agent must immediately
        // disconnect."
        if (status.result != msgs::AuthStatusResult::kAuthenticated &&
            !state->failed) {
          state->failed = true;
          state->authenticated = false;
          delegate_->OnAuthenticationFailed(
              instance_id, Error(Error::Code::kOperationCancelled,
                                 "peer reported authentication failure"));
        }
      }
      return result;
    }

    default:
      return Error::Code::kUnknownMessageType;
  }
}

bool AgentAuthenticator::IsPresenter(const State& state) const {
  // network.bs: "The agent with the lowest PSK ease of input presents a PSK to
  // the user [...] In case both agents have the same PSK ease of input value,
  // the server presents the PSK to the user."
  OSP_CHECK(state.peer_capabilities);
  const uint64_t local = config_.psk_ease_of_input;
  const uint64_t remote = state.peer_capabilities->psk_ease_of_input;
  if (local == remote) {
    return state.peer.local_is_server;
  }
  return local < remote;
}

std::string AgentAuthenticator::ObtainPsk(State& state, bool presenter) {
  if (!state.psk.empty()) {
    return state.psk;
  }
  std::string psk = CanonicalizePsk(config_.psk);
  if (psk.empty() && presenter) {
    // network.bs: "The PSK presenter must generate a PSK that has at least as
    // many bits of entropy as it receives in this field, and at least as many
    // bits of entropy as it sends in this field."
    uint64_t bits = config_.psk_min_bits_of_entropy;
    if (state.peer_capabilities) {
      bits = std::max(bits, state.peer_capabilities->psk_min_bits_of_entropy);
    }
    psk = GeneratePsk(bits);
  }
  if (!psk.empty() && presenter) {
    OSP_LOG_INFO << "PSK presenter: show this PSK to the user: "
                 << FormatPskForDisplay(psk);
  }
  state.psk = psk;
  return psk;
}

ErrorOr<std::unique_ptr<Spake2>> AgentAuthenticator::CreateSpake2(
    const State& state,
    bool is_alice,
    const std::string& psk) const {
  if (config_.spake2_suite != AuthenticationConfig::Spake2Suite::kP256) {
    return Error(Error::Code::kNotImplemented,
                 "the network.bs SPAKE2 suite (edwards25519) is not "
                 "implemented; the P-256 suite is available as a non-spec "
                 "option (osp_demo: --spake2_suite=p256)");
  }
  Spake2::Options options;
  options.role = is_alice ? Spake2::Role::kA : Spake2::Role::kB;

  const AgentFingerprint& client_fp = state.peer.local_is_server
                                          ? state.peer.peer_fingerprint
                                          : state.peer.local_fingerprint;
  const AgentFingerprint& server_fp = state.peer.local_is_server
                                          ? state.peer.local_fingerprint
                                          : state.peer.peer_fingerprint;
  switch (config_.spake2_identities) {
    case AuthenticationConfig::Spake2Identities::kClientServer:
      options.identity_a = ToBytes(client_fp);
      options.identity_b = ToBytes(server_fp);
      break;
    case AuthenticationConfig::Spake2Identities::kAliceBob:
      options.identity_a = ToBytes(is_alice ? state.peer.local_fingerprint
                                            : state.peer.peer_fingerprint);
      options.identity_b = ToBytes(is_alice ? state.peer.peer_fingerprint
                                            : state.peer.local_fingerprint);
      break;
  }
  options.password_hash =
      config_.spake2_password_hash ==
              AuthenticationConfig::Spake2PasswordHash::kSha512
          ? Spake2::PasswordHash::kSha512
          : Spake2::PasswordHash::kSha256;
  return Spake2::Create(options, ToBytes(psk));
}

void AgentAuthenticator::MaybeInitiate(uint64_t instance_id, State& state) {
  if (!config_.enabled || state.spake2 || state.failed || state.authenticated ||
      !IsPresenter(state)) {
    return;
  }
  // network.bs: "If the PSK presenter wants to initiate authentication, it
  // starts the authentication process by presenting the PSK to the user and
  // sending a auth-spake2-handshake message. The public-value field [...] must
  // be set to the value of pA from SPAKE2 and the psk-status field must be set
  // to psk-shown."
  //
  // The PSK consumer never initiates here; it waits for the presenter.
  const std::string psk = ObtainPsk(state, /*presenter=*/true);
  auto spake2 = CreateSpake2(state, /*is_alice=*/true, psk);
  if (!spake2) {
    Fail(instance_id, state, msgs::AuthStatusResult::kUnknownError,
         spake2.error());
    return;
  }
  state.is_alice = true;
  state.spake2 = std::move(spake2.value());
  OSP_LOG_INFO << "SPAKE2: initiating as Alice (PSK presenter) with "
               << state.peer.peer_name;
  SendHandshake(state, msgs::AuthSpake2PskStatus::kPskShown);
}

void AgentAuthenticator::HandleHandshake(
    uint64_t instance_id,
    State& state,
    const msgs::AuthSpake2Handshake& message) {
  // network.bs: "Agents should discard any authentication message whose
  // auth-initation-token is set and does not match the at provided by the
  // advertising agent."
  if (message.initiation_token.token &&
      *message.initiation_token.token != state.peer.auth_token) {
    OSP_LOG_WARN << "Discarding auth-spake2-handshake from "
                 << state.peer.peer_name
                 << ": auth-initiation-token does not match at";
    return;
  }
  if (!config_.enabled || state.failed || state.authenticated) {
    return;
  }
  OSP_LOG_INFO << "auth-spake2-handshake from " << state.peer.peer_name
               << ": psk-status=" << message.psk_status << " public-value "
               << message.public_value.size() << " bytes";

  if (state.spake2 && state.is_alice) {
    if (message.psk_status ==
        msgs::AuthSpake2PskStatus::kPskNeedsPresentation) {
      // Both agents initiated. network.bs does not say how to resolve this;
      // keep the presenter's initiation, which the peer will answer.
      OSP_LOG_WARN << "Both agents initiated SPAKE2; ignoring the "
                      "psk-needs-presentation handshake from "
                   << state.peer.peer_name;
      return;
    }
    // The peer's reply carries pB.
    if (state.sent_confirmation) {
      return;
    }
    Error error = state.spake2->ProcessPeerShare(message.public_value);
    if (!error.ok()) {
      Fail(instance_id, state, msgs::AuthStatusResult::kProofInvalid, error);
      return;
    }
    MaybeSendConfirmation(state);
    MaybeVerifyPeerConfirmation(instance_id, state);
    return;
  }
  if (state.spake2) {
    OSP_LOG_WARN << "Ignoring repeated auth-spake2-handshake from "
                 << state.peer.peer_name;
    return;
  }

  // The peer initiated, so the local agent is Bob. Either the presenter showed
  // the PSK (psk-shown), or the consumer asks the presenter to show one
  // (psk-needs-presentation).
  const bool presenter =
      message.psk_status == msgs::AuthSpake2PskStatus::kPskNeedsPresentation;
  const std::string psk = ObtainPsk(state, presenter);
  if (psk.empty()) {
    // network.bs: "the PSK consumer prompts the user for the PSK input". This
    // implementation takes the user's input from the configuration.
    OSP_LOG_ERROR << "PSK consumer: a PSK is required to authenticate "
                  << state.peer.peer_name << " (osp_demo: --psk)";
    Fail(instance_id, state, msgs::AuthStatusResult::kSecretUnknown,
         Error(Error::Code::kParameterInvalid, "no PSK available"));
    return;
  }
  auto spake2 = CreateSpake2(state, /*is_alice=*/false, psk);
  if (!spake2) {
    Fail(instance_id, state, msgs::AuthStatusResult::kUnknownError,
         spake2.error());
    return;
  }
  state.is_alice = false;
  state.spake2 = std::move(spake2.value());
  Error error = state.spake2->ProcessPeerShare(message.public_value);
  if (!error.ok()) {
    Fail(instance_id, state, msgs::AuthStatusResult::kProofInvalid, error);
    return;
  }
  OSP_LOG_INFO << "SPAKE2: responding as Bob to " << state.peer.peer_name;
  // network.bs: "it sends an auth-spake2-handshake message with the
  // public-value field set to the value of pB from SPAKE2 and the psk-status
  // field set to psk-input."
  SendHandshake(state, msgs::AuthSpake2PskStatus::kPskInput);
  // network.bs: "Once an agent knows both pA and pB from auth-spake2-handshake
  // messages, it computes and sends a auth-spake2-confirmation".
  MaybeSendConfirmation(state);
  MaybeVerifyPeerConfirmation(instance_id, state);
}

void AgentAuthenticator::HandleConfirmation(
    uint64_t instance_id,
    State& state,
    const std::vector<uint8_t>& confirmation) {
  if (!config_.enabled || state.failed || state.authenticated) {
    return;
  }
  OSP_LOG_INFO << "auth-spake2-confirmation from " << state.peer.peer_name
               << " (" << confirmation.size() << " bytes)";
  state.peer_confirmation = confirmation;
  MaybeVerifyPeerConfirmation(instance_id, state);
}

void AgentAuthenticator::MaybeSendConfirmation(State& state) {
  if (state.sent_confirmation) {
    return;
  }
  msgs::AuthSpake2Confirmation message;
  message.confirmation_value = state.spake2->GetConfirmation();
  Send(state, message, &msgs::EncodeAuthSpake2Confirmation);
  state.sent_confirmation = true;
}

void AgentAuthenticator::MaybeVerifyPeerConfirmation(uint64_t instance_id,
                                                     State& state) {
  if (!state.sent_confirmation || state.peer_confirmation.empty() ||
      state.authenticated || state.failed) {
    return;
  }
  // network.bs: "Once an agent receives an auth-spake2-confirmation message,
  // it validates that message using the procedure in [SPAKE2] and then replies
  // with an auth-status authenticated message to the other agent."
  Error error = state.spake2->VerifyPeerConfirmation(state.peer_confirmation);
  if (!error.ok()) {
    Fail(instance_id, state, msgs::AuthStatusResult::kProofInvalid, error);
    return;
  }
  msgs::AuthStatus status;
  status.result = msgs::AuthStatusResult::kAuthenticated;
  Send(state, status, &msgs::EncodeAuthStatus);
  state.authenticated = true;
  state.timeout_alarm.reset();
  OSP_LOG_INFO << "SPAKE2: authenticated " << state.peer.peer_name << " as "
               << (state.is_alice ? "Alice" : "Bob");
  delegate_->OnAuthenticationSucceeded(instance_id);
}

void AgentAuthenticator::OnTimeout(uint64_t instance_id) {
  auto it = states_.find(instance_id);
  if (it == states_.end()) {
    return;
  }
  State& state = *it->second;
  if (state.authenticated || state.failed) {
    return;
  }
  Fail(
      instance_id, state, msgs::AuthStatusResult::kTimeout,
      Error(Error::Code::kOperationCancelled,
            "authentication did not complete within " +
                std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                                   config_.timeout)
                                   .count()) +
                " s"));
}

void AgentAuthenticator::Fail(uint64_t instance_id,
                              State& state,
                              msgs::AuthStatusResult result,
                              const Error& error) {
  if (state.failed) {
    return;
  }
  state.failed = true;
  state.timeout_alarm.reset();
  OSP_LOG_WARN << "Authentication with " << state.peer.peer_name
               << " failed: " << error << " (auth-status " << result << ")";
  msgs::AuthStatus status;
  status.result = result;
  Send(state, status, &msgs::EncodeAuthStatus);
  delegate_->OnAuthenticationFailed(instance_id, error);
}

void AgentAuthenticator::SendHandshake(State& state,
                                       msgs::AuthSpake2PskStatus status) {
  msgs::AuthSpake2Handshake message;
  // network.bs: "For an advertising agent, the at field in its mDNS TXT record
  // must be used as the auth-initation-token in the the first authentication
  // message sent to or from that agent." Each side sends at most one
  // handshake, so always including it is simplest.
  message.initiation_token.token = state.peer.auth_token;
  message.psk_status = status;
  message.public_value = state.spake2->GetPublicShare();
  Send(state, message, &msgs::EncodeAuthSpake2Handshake);
}

template <typename T>
void AgentAuthenticator::Send(State& state,
                              const T& message,
                              MessageEncodingFunction<T> encoder) {
  // All network-phase messages to a peer go on one stream, so they arrive in
  // order (network.bs: "To send a group of messages in order, that group of
  // messages must be sent in one QUIC stream.").
  Error error = state.sender->WriteMessage(message, encoder);
  if (!error.ok()) {
    OSP_LOG_WARN << "Failed to send to " << state.peer.peer_name << ": "
                 << error;
  }
}

// static
std::string AgentAuthenticator::CanonicalizePsk(std::string_view psk) {
  std::string digits;
  for (char c : psk) {
    if (c == '-' || c == ' ' || c == '\t') {
      continue;
    }
    if (c < '0' || c > '9') {
      return {};
    }
    if (digits.empty() && c == '0') {
      continue;  // "Remove dashes and leading zeros from N."
    }
    digits.push_back(c);
  }
  return digits;
}

// static
std::string AgentAuthenticator::FormatPskForDisplay(
    std::string_view canonical_psk) {
  std::string n(canonical_psk);
  // "If N has fewer than 9 digits: Zero-pad N on the left with
  // 3 - len(N) mod 3 digits. Output N in groups of three digits separated by
  // dashes." and four-digit groups otherwise. Padding is only applied when it
  // is needed to fill a group.
  const size_t group = n.size() < 9 ? 3 : 4;
  if (n.size() % group != 0) {
    n.insert(0, group - n.size() % group, '0');
  }
  std::string out;
  for (size_t i = 0; i < n.size(); i += group) {
    if (!out.empty()) {
      out.push_back('-');
    }
    out.append(n, i, group);
  }
  return out;
}

// static
std::string AgentAuthenticator::GeneratePsk(uint64_t bits) {
  bits = std::clamp(bits, kMinPskBits, kMaxPskBits);
  uint8_t bytes[8];
  GenerateRandomBytes(bytes);
  uint64_t value = 0;
  for (uint8_t b : bytes) {
    value = (value << 8) | b;
  }
  value &= (uint64_t{1} << bits) - 1;
  std::string psk = std::to_string(value);
  return psk == "0" ? "1" : psk;
}

}  // namespace openscreen::osp

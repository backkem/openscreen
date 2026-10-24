// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OSP_PUBLIC_AUTHENTICATION_CONFIG_H_
#define OSP_PUBLIC_AUTHENTICATION_CONFIG_H_

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "osp/msgs/osp_messages.h"

namespace openscreen::osp {

// Configuration of the network.bs "Authentication" phase, and of the agent
// metadata (agent-info) that is exchanged before it.
//
// Options marked NON-SPEC deviate from network.bs. They exist for debugging
// and interop experiments only and default to the spec behavior.
struct AuthenticationConfig {
  // Which fingerprints are used as the SPAKE2 identities A and B.
  enum class Spake2Identities {
    // network.bs: "The values A and B used in SPAKE2 are the agent
    // fingerprints of the client and server, respectively."
    kClientServer,
    // NON-SPEC: A is the fingerprint of the agent acting as SPAKE2 Alice (the
    // initiator) and B the one of Bob. This is what openscreen-go does.
    kAliceBob,
  };

  // The password hash used to derive the SPAKE2 scalar w from the PSK.
  enum class Spake2PasswordHash {
    // network.bs: "Password hash function is SHA-512."
    kSha512,
    // NON-SPEC: SHA-256, as openscreen-go does.
    kSha256,
  };

  // The SPAKE2 ciphersuite.
  enum class Spake2Suite {
    // network.bs: "Elliptic curve is edwards25519. Hash function is SHA-256.
    // Key derivation function is HKDF. Message authentication code is HMAC."
    // NOT IMPLEMENTED: BoringSSL's public API offers no general edwards25519
    // group operations (EC_GROUP custom curves must have cofactor 1 and
    // p < 2*order, and the curve25519 SPAKE2_* API is not RFC 9382), so
    // authentication fails with this suite.
    kEdwards25519,
    // NON-SPEC: RFC 9382 SPAKE2-P256-SHA256-HKDF-HMAC, which openscreen-go
    // uses.
    kP256,
  };

  // NON-SPEC when false: skip authentication entirely and treat every peer
  // as authenticated (the behavior before authentication was implemented).
  bool enabled = true;

  // NON-SPEC when true: deliver application messages from peers that have not
  // completed authentication. network.bs: "it must treat that agent as
  // unverified and initiate authentication with that agent before allowing
  // additional messages to be exchanged with that agent."
  bool allow_unauthenticated_messages = false;

  // The PSK, as a numeric string (dashes and whitespace are ignored). When
  // this agent is the PSK presenter and `psk` is empty, a random PSK is
  // generated and logged ("presented"). When this agent is the PSK consumer,
  // `psk` stands for the user's input and must be set.
  std::string psk;

  // Sent in auth-capabilities. network.bs: "PSK ease of input is an integer in
  // the range from 0 to 100 inclusive".
  uint64_t psk_ease_of_input = 50;

  // Sent in auth-capabilities, "in the range of 20 to 60 bits inclusive, with
  // a default of 20."
  uint64_t psk_min_bits_of_entropy = 20;

  // How long authentication may take from the end of the QUIC handshake
  // before the agent gives up, sends auth-status `timeout` and closes the
  // connection. network.bs sets no limit; this only bounds how long an
  // unauthenticated connection is kept, for example when the peer never
  // answers. It includes the time the user needs to enter a PSK.
  std::chrono::milliseconds timeout = std::chrono::seconds(60);

  Spake2Suite spake2_suite = Spake2Suite::kEdwards25519;
  Spake2Identities spake2_identities = Spake2Identities::kClientServer;
  Spake2PasswordHash spake2_password_hash = Spake2PasswordHash::kSha512;
};

// The local agent-info, sent in agent-info-response.
struct AgentInfoConfig {
  std::string display_name;
  std::string model_name;
  std::vector<msgs::AgentCapability> capabilities;
  std::vector<std::string> locales;
};

}  // namespace openscreen::osp

#endif  // OSP_PUBLIC_AUTHENTICATION_CONFIG_H_

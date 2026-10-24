// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OSP_PUBLIC_AUTHENTICATION_CONFIG_H_
#define OSP_PUBLIC_AUTHENTICATION_CONFIG_H_

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

  Spake2Suite spake2_suite = Spake2Suite::kEdwards25519;
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

// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UTIL_CRYPTO_SPAKE2_H_
#define UTIL_CRYPTO_SPAKE2_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "platform/base/error.h"
#include "platform/base/span.h"

namespace openscreen {

// RFC 9382 SPAKE2 with the "SPAKE2-P256-SHA256-HKDF-HMAC" ciphersuite: group
// P-256, hash SHA-256, KDF HKDF-SHA256 and MAC HMAC-SHA256, with explicit key
// confirmation (RFC 9382 section 4).
//
// Ported from https://github.com/backkem/spake2_cpp (MIT) and rewritten
// against BoringSSL primitives.
//
// The interface is intentionally narrow so the implementation can later be
// replaced by an RFC 9382 API provided by BoringSSL. A single instance runs a
// single protocol execution:
//
//   auto a = Spake2::Create({.role = Spake2::Role::kA, ...}, password);
//   send(a->GetPublicShare());            // pA (or pB for role kB).
//   a->ProcessPeerShare(received_share);  // pB (or pA).
//   send(a->GetConfirmation());           // cA (or cB).
//   a->VerifyPeerConfirmation(received_confirmation);
//   a->shared_key();                      // Ke.
//
// Since SPAKE2 is a one round protocol, either role can compute its public
// share before having received the peer's share.
class Spake2 {
 public:
  enum class Role {
    kA,  // The RFC's "A" (Alice).
    kB,  // The RFC's "B" (Bob).
  };

  // The function used to map the password to the scalar w ("w = MHF(pw) mod
  // p", RFC 9382 section 3.2).
  enum class PasswordHash {
    kSha256,
    kSha512,
  };

  struct Options {
    Role role = Role::kA;
    // The identities A and B, used in the transcript TT.
    std::vector<uint8_t> identity_a;
    std::vector<uint8_t> identity_b;
    // Optional associated data, mixed into the confirmation key derivation.
    std::vector<uint8_t> aad;
    PasswordHash password_hash = PasswordHash::kSha256;
  };

  // Creates an instance with a fresh random ephemeral scalar. `password` is
  // hashed with `options.password_hash` to derive w.
  static ErrorOr<std::unique_ptr<Spake2>> Create(const Options& options,
                                                 ByteView password);

  // Creates an instance with a fixed w and ephemeral scalar (x for role A, y
  // for role B), both big-endian. Only meant for the RFC 9382 test vectors.
  static ErrorOr<std::unique_ptr<Spake2>> CreateForTesting(
      const Options& options,
      ByteView w,
      ByteView ephemeral_scalar);

  Spake2(const Spake2&) = delete;
  Spake2& operator=(const Spake2&) = delete;
  ~Spake2();

  // Returns pA = w*M + X (role A) or pB = w*N + Y (role B), as an uncompressed
  // SEC1 point.
  const std::vector<uint8_t>& GetPublicShare() const { return public_share_; }

  // Processes the peer's public share and derives the keys. Must be called
  // exactly once.
  Error ProcessPeerShare(ByteView peer_share);

  // Returns cA (role A) or cB (role B). Only valid after `ProcessPeerShare`.
  const std::vector<uint8_t>& GetConfirmation() const;

  // Verifies cB (role A) or cA (role B) in constant time. Only valid after
  // `ProcessPeerShare`.
  Error VerifyPeerConfirmation(ByteView peer_confirmation);

  // Returns Ke. Only valid after a successful `VerifyPeerConfirmation`.
  const std::vector<uint8_t>& shared_key() const;

  bool is_confirmed() const { return confirmed_; }

  // Exposed for tests.
  const std::vector<uint8_t>& transcript_for_testing() const {
    return transcript_;
  }

 private:
  struct Impl;

  Spake2(const Options& options, std::unique_ptr<Impl> impl);
  Error Initialize();

  const Options options_;
  std::unique_ptr<Impl> impl_;

  std::vector<uint8_t> public_share_;
  std::vector<uint8_t> transcript_;
  std::vector<uint8_t> shared_key_;             // Ke.
  std::vector<uint8_t> confirmation_key_;       // KcA (role A) or KcB (role B).
  std::vector<uint8_t> peer_confirmation_key_;  // KcB (role A) or KcA (role B).
  std::vector<uint8_t> confirmation_;
  bool keys_derived_ = false;
  bool confirmed_ = false;
};

}  // namespace openscreen

#endif  // UTIL_CRYPTO_SPAKE2_H_

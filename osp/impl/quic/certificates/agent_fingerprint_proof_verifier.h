// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OSP_IMPL_QUIC_CERTIFICATES_AGENT_FINGERPRINT_PROOF_VERIFIER_H_
#define OSP_IMPL_QUIC_CERTIFICATES_AGENT_FINGERPRINT_PROOF_VERIFIER_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "osp/public/agent_certificate.h"
#include "quiche/quic/core/crypto/proof_verifier.h"

namespace openscreen::osp {

// Verifies a server's agent certificate by pinning its agent fingerprint, as
// required by network.bs section "TLS 1.3": "The agent fingerprint calculated
// for the received agent certificate must match the `fp` mDNS TXT record as
// advertised by the advertising agent."
//
// The agent fingerprint is the base64-encoded SHA-256 SPKI fingerprint (see
// QuicAgentCertificate::ComputeAgentFingerprint). Fingerprints are pinned per
// TLS server name, so one verifier can serve connections to several agents.
class AgentFingerprintProofVerifier final : public quic::ProofVerifier {
 public:
  AgentFingerprintProofVerifier();
  ~AgentFingerprintProofVerifier() override;

  // Sets (or replaces) the expected agent fingerprint for `hostname`.
  void SetFingerprint(const std::string& hostname,
                      const AgentFingerprint& fingerprint);

  // quic::ProofVerifier overrides.
  quic::QuicAsyncStatus VerifyProof(
      const std::string& hostname,
      const uint16_t port,
      const std::string& server_config,
      quic::QuicTransportVersion transport_version,
      absl::string_view chlo_hash,
      const std::vector<std::string>& certs,
      const std::string& cert_sct,
      const std::string& signature,
      const quic::ProofVerifyContext* context,
      std::string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* details,
      std::unique_ptr<quic::ProofVerifierCallback> callback) override;
  quic::QuicAsyncStatus VerifyCertChain(
      const std::string& hostname,
      const uint16_t port,
      const std::vector<std::string>& certs,
      const std::string& ocsp_response,
      const std::string& cert_sct,
      const quic::ProofVerifyContext* context,
      std::string* error_details,
      std::unique_ptr<quic::ProofVerifyDetails>* details,
      uint8_t* out_alert,
      std::unique_ptr<quic::ProofVerifierCallback> callback) override;
  std::unique_ptr<quic::ProofVerifyContext> CreateDefaultContext() override;

 private:
  std::map<std::string, AgentFingerprint> fingerprints_;
};

}  // namespace openscreen::osp

#endif  // OSP_IMPL_QUIC_CERTIFICATES_AGENT_FINGERPRINT_PROOF_VERIFIER_H_

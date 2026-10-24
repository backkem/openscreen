// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/impl/quic/certificates/agent_fingerprint_proof_verifier.h"

#include <utility>

#include "osp/impl/quic/certificates/quic_agent_certificate.h"
#include "util/osp_logging.h"

namespace openscreen::osp {

AgentFingerprintProofVerifier::AgentFingerprintProofVerifier() = default;

AgentFingerprintProofVerifier::~AgentFingerprintProofVerifier() = default;

void AgentFingerprintProofVerifier::SetFingerprint(
    const std::string& hostname,
    const AgentFingerprint& fingerprint) {
  fingerprints_[hostname] = fingerprint;
}

quic::QuicAsyncStatus AgentFingerprintProofVerifier::VerifyProof(
    const std::string& /*hostname*/,
    const uint16_t /*port*/,
    const std::string& /*server_config*/,
    quic::QuicTransportVersion /*transport_version*/,
    absl::string_view /*chlo_hash*/,
    const std::vector<std::string>& /*certs*/,
    const std::string& /*cert_sct*/,
    const std::string& /*signature*/,
    const quic::ProofVerifyContext* /*context*/,
    std::string* error_details,
    std::unique_ptr<quic::ProofVerifyDetails>* /*details*/,
    std::unique_ptr<quic::ProofVerifierCallback> /*callback*/) {
  // Only used by QUIC crypto; OSP requires TLS 1.3.
  *error_details = "QUIC crypto proofs are not supported";
  return quic::QUIC_FAILURE;
}

quic::QuicAsyncStatus AgentFingerprintProofVerifier::VerifyCertChain(
    const std::string& hostname,
    const uint16_t /*port*/,
    const std::vector<std::string>& certs,
    const std::string& /*ocsp_response*/,
    const std::string& /*cert_sct*/,
    const quic::ProofVerifyContext* /*context*/,
    std::string* error_details,
    std::unique_ptr<quic::ProofVerifyDetails>* /*details*/,
    uint8_t* /*out_alert*/,
    std::unique_ptr<quic::ProofVerifierCallback> /*callback*/) {
  if (certs.empty()) {
    *error_details = "No certificates provided";
    return quic::QUIC_FAILURE;
  }

  auto it = fingerprints_.find(hostname);
  if (it == fingerprints_.end()) {
    *error_details = "No agent fingerprint known for " + hostname;
    return quic::QUIC_FAILURE;
  }

  const AgentFingerprint fingerprint =
      QuicAgentCertificate::ComputeAgentFingerprint(certs[0]);
  if (fingerprint.empty()) {
    *error_details = "Failed to parse the agent certificate";
    return quic::QUIC_FAILURE;
  }
  if (fingerprint != it->second) {
    *error_details = "Agent fingerprint " + fingerprint +
                     " does not match advertised fp " + it->second;
    OSP_LOG_WARN << *error_details;
    return quic::QUIC_FAILURE;
  }
  return quic::QUIC_SUCCESS;
}

std::unique_ptr<quic::ProofVerifyContext>
AgentFingerprintProofVerifier::CreateDefaultContext() {
  return nullptr;
}

}  // namespace openscreen::osp

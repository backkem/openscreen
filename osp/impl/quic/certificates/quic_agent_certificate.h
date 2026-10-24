// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OSP_IMPL_QUIC_CERTIFICATES_QUIC_AGENT_CERTIFICATE_H_
#define OSP_IMPL_QUIC_CERTIFICATES_QUIC_AGENT_CERTIFICATE_H_

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "openssl/base.h"
#include "osp/public/agent_certificate.h"
#include "platform/base/span.h"
#include "quiche/quic/core/crypto/client_proof_source.h"
#include "quiche/quic/core/crypto/proof_source.h"

namespace openscreen::osp {

class QuicAgentCertificate final : public AgentCertificate {
 public:
  QuicAgentCertificate();
  QuicAgentCertificate(const QuicAgentCertificate&) = delete;
  QuicAgentCertificate& operator=(const QuicAgentCertificate&) = delete;
  QuicAgentCertificate(QuicAgentCertificate&&) noexcept = delete;
  QuicAgentCertificate& operator=(QuicAgentCertificate&&) noexcept = delete;
  ~QuicAgentCertificate() override;

  // Computes the agent fingerprint of a DER-encoded agent certificate, as
  // defined by network.bs "Computing the Agent Fingerprint": the base64
  // encoding of the RFC 7469 SPKI fingerprint (SHA-256 over the DER-encoded
  // SubjectPublicKeyInfo). Returns an empty string on failure.
  static AgentFingerprint ComputeAgentFingerprint(std::string_view der_cert);

  // The identity-dependent fields of an agent certificate, network.bs "Agent
  // Certificates".
  struct Identity {
    // Issuer CN: "The model-name from the agent-info message".
    std::string model_name;
    // DNS-SD Service Instance Name and domain, which make up the Subject CN
    // (the agent hostname). A listening agent has no instance name; it uses
    // its display name instead.
    std::string instance_name;
    std::string domain = "local";
  };

  // network.bs "Computing the Certificate Serial Number": 160 bits.
  static constexpr size_t kSerialNumberSize = 20;
  using SerialNumber = std::array<uint8_t, kSerialNumberSize>;

  // network.bs "Computing the Agent Hostname": the base64 serial number, the
  // instance name and the domain, joined by dots, with any character of the
  // latter two other than [A-Za-z0-9-] replaced by a hyphen.
  static std::string ComputeAgentHostname(const SerialNumber& serial_number,
                                          std::string_view instance_name,
                                          std::string_view domain);

  // Makes the active agent certificate carry the network.bs fields for
  // `identity`. Unless the active certificate already does, a new one is
  // generated in memory for the active private key, with the next
  // certificate serial number. The SPKI, and so the agent fingerprint, does
  // not change. A listening agent passes `overwrite` = false so that it does
  // not replace the identity of an advertising agent in the same process.
  // Returns false on failure.
  bool SetIdentity(const Identity& identity, bool overwrite);

  // Returns the active DER-encoded agent certificate, or an empty string.
  std::string GetCertificateDer() const;

  // AgentCertificate overrides.
  bool LoadAgentCertificate(std::string_view filename) override;
  bool LoadPrivateKey(std::string_view filename) override;
  bool RotateAgentCertificate() override;
  AgentFingerprint GetAgentFingerprint() override;

  // Create a ProofSource for server using currently active agent certificate
  // and private key.
  std::unique_ptr<quic::ProofSource> CreateServerProofSource();

  // Create a ProofSource for client using currently active agent certificate
  // and private key.
  std::unique_ptr<quic::ClientProofSource> CreateClientProofSource(
      std::string_view server_hostname);

  void ResetCredentials();

 private:
  // Generate private key and agent certificate to the specified file for
  // use.
  // Returns true if generates credentials succeed, false otherwise.
  bool GenerateCredentialsToFile();

  // Load private key and agent certificate from the specified files for
  // use.
  // Returns true if loads credentials succeed, false otherwise.
  bool LoadCredentials();

  // Generates and activates the agent certificate for `identity_`.
  bool ApplyIdentity();

  std::optional<Identity> identity_;

  AgentFingerprint agent_fingerprint_;
  std::vector<std::string> certificates_;
  bssl::UniquePtr<EVP_PKEY> key_;
};

}  // namespace openscreen::osp

#endif  // OSP_IMPL_QUIC_CERTIFICATES_QUIC_AGENT_CERTIFICATE_H_

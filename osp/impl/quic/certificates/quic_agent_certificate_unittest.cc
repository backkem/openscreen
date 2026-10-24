// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/impl/quic/certificates/quic_agent_certificate.h"

#include <string>

#include "gtest/gtest.h"
#include "openssl/bn.h"
#include "openssl/x509.h"
#include "util/base64.h"

namespace openscreen::osp {
namespace {

bssl::UniquePtr<X509> Parse(const std::string& der) {
  const uint8_t* data = reinterpret_cast<const uint8_t*>(der.data());
  return bssl::UniquePtr<X509>(d2i_X509(nullptr, &data, der.size()));
}

std::string CommonName(X509_NAME* name) {
  const int index = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
  if (index < 0) {
    return {};
  }
  const ASN1_STRING* data =
      X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, index));
  return std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(data)),
                     ASN1_STRING_length(data));
}

QuicAgentCertificate::SerialNumber Serial(X509* certificate) {
  bssl::UniquePtr<BIGNUM> bn(
      ASN1_INTEGER_to_BN(X509_get0_serialNumber(certificate), nullptr));
  QuicAgentCertificate::SerialNumber serial{};
  EXPECT_TRUE(BN_bn2bin_padded(serial.data(), serial.size(), bn.get()));
  return serial;
}

TEST(QuicAgentCertificateTest, ComputeAgentHostname) {
  QuicAgentCertificate::SerialNumber serial{};
  serial[19] = 1;
  EXPECT_EQ(base64::Encode(ByteView(serial)) + ".Living-Room-TV--2-.local",
            QuicAgentCertificate::ComputeAgentHostname(
                serial, "Living Room TV (2)", "local"));
}

TEST(QuicAgentCertificateTest, SetIdentity) {
  QuicAgentCertificate certificate;
  const AgentFingerprint fingerprint = certificate.GetAgentFingerprint();
  ASSERT_FALSE(fingerprint.empty());

  QuicAgentCertificate::Identity identity;
  identity.model_name = "Model X";
  identity.instance_name = "Kitchen display";
  ASSERT_TRUE(certificate.SetIdentity(identity, /*overwrite=*/true));
  // The SPKI, and so the agent fingerprint, stays the same.
  EXPECT_EQ(fingerprint, certificate.GetAgentFingerprint());

  const std::string der = certificate.GetCertificateDer();
  bssl::UniquePtr<X509> x509 = Parse(der);
  ASSERT_TRUE(x509);
  EXPECT_EQ(X509_VERSION_3, X509_get_version(x509.get()));
  EXPECT_EQ("Model X", CommonName(X509_get_issuer_name(x509.get())));
  const QuicAgentCertificate::SerialNumber serial = Serial(x509.get());
  EXPECT_EQ(QuicAgentCertificate::ComputeAgentHostname(
                serial, "Kitchen display", "local"),
            CommonName(X509_get_subject_name(x509.get())));
  // The certificate serial number counter starts at 1.
  EXPECT_EQ(0, serial[16]);
  EXPECT_EQ(0, serial[17]);
  EXPECT_EQ(0, serial[18]);
  EXPECT_EQ(1, serial[19]);
  // Key usage is digitalSignature only, and the certificate is not a CA.
  EXPECT_EQ(static_cast<uint32_t>(X509v3_KU_DIGITAL_SIGNATURE),
            X509_get_key_usage(x509.get()));
  EXPECT_EQ(0, X509_check_ca(x509.get()));
  // Self-signed: the signature verifies with its own key.
  bssl::UniquePtr<EVP_PKEY> key(X509_get_pubkey(x509.get()));
  EXPECT_EQ(1, X509_verify(x509.get(), key.get()));

  // The same identity keeps the certificate.
  ASSERT_TRUE(certificate.SetIdentity(identity, /*overwrite=*/true));
  EXPECT_EQ(der, certificate.GetCertificateDer());

  // A listening agent does not overwrite the identity.
  QuicAgentCertificate::Identity other;
  other.model_name = "Other";
  other.instance_name = "Other";
  ASSERT_TRUE(certificate.SetIdentity(other, /*overwrite=*/false));
  EXPECT_EQ(der, certificate.GetCertificateDer());

  // A new instance name gives a new certificate with the same serial number
  // base and the next counter value.
  identity.instance_name = "Kitchen";
  ASSERT_TRUE(certificate.SetIdentity(identity, /*overwrite=*/true));
  x509 = Parse(certificate.GetCertificateDer());
  ASSERT_TRUE(x509);
  const QuicAgentCertificate::SerialNumber next = Serial(x509.get());
  EXPECT_TRUE(std::equal(serial.begin(), serial.begin() + 16, next.begin()));
  EXPECT_EQ(2, next[19]);
  EXPECT_EQ(fingerprint, certificate.GetAgentFingerprint());
}

}  // namespace
}  // namespace openscreen::osp

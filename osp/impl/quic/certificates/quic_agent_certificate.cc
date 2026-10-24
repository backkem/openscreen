// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/impl/quic/certificates/quic_agent_certificate.h"

#include <chrono>
#include <utility>

#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/nid.h"
#include "openssl/x509.h"
#include "quiche/quic/core/crypto/proof_source_x509.h"
#include "quiche/quic/core/quic_utils.h"
#include "util/base64.h"
#include "util/crypto/certificate_utils.h"
#include "util/crypto/pem_helpers.h"
#include "util/crypto/random_bytes.h"
#include "util/osp_logging.h"
#include "util/read_file.h"

namespace openscreen::osp {

namespace {

using FileUniquePtr = std::unique_ptr<FILE, decltype(&fclose)>;

constexpr char kCertificatesPath[] =
    "osp/impl/quic/certificates/agent_certificate.crt";
constexpr char kPrivateKeyPath[] = "osp/impl/quic/certificates/private_key.key";
constexpr int kOneYearInSeconds = 365 * 24 * 60 * 60;
constexpr auto kCertificateDuration = std::chrono::seconds(kOneYearInSeconds);

bssl::UniquePtr<EVP_PKEY> GeneratePrivateKey() {
  bssl::UniquePtr<EVP_PKEY_CTX> ctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_EC, /*e=*/nullptr));
  OSP_CHECK(EVP_PKEY_keygen_init(ctx.get()));
  OSP_CHECK(
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1));
  EVP_PKEY* key = nullptr;
  OSP_CHECK(EVP_PKEY_keygen(ctx.get(), &key));
  return bssl::UniquePtr<EVP_PKEY>(key);
}

// TODO(issuetracker.google.com/300236996): There are currently some spec issues
// about certificates that are still under discussion. Make all fields of the
// certificate comply with the requirements of the spec once all the issues are
// closed.
bssl::UniquePtr<X509> GenerateRootCert(const EVP_PKEY& root_key) {
  ErrorOr<bssl::UniquePtr<X509>> root_cert_or_error =
      CreateSelfSignedX509Certificate("Open Screen Certificate",
                                      kCertificateDuration, root_key,
                                      GetWallTimeSinceUnixEpoch(), true);
  OSP_CHECK(root_cert_or_error);
  return std::move(root_cert_or_error.value());
}

std::string EncodeHostnameLabel(std::string_view label) {
  std::string out(label);
  for (char& c : out) {
    const bool allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                         (c >= '0' && c <= '9') || c == '-';
    if (!allowed) {
      c = '-';
    }
  }
  return out;
}

std::string GetCommonName(X509_NAME* name) {
  const int index = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
  if (index < 0) {
    return {};
  }
  const ASN1_STRING* data =
      X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, index));
  return std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(data)),
                     ASN1_STRING_length(data));
}

bool AddCommonName(X509_NAME* name, std::string_view value) {
  // V_ASN1_UTF8STRING rather than MBSTRING_UTF8, which would limit the CN to
  // the 64 characters of ub-common-name. An agent hostname can be longer.
  return X509_NAME_add_entry_by_NID(
             name, NID_commonName, V_ASN1_UTF8STRING,
             reinterpret_cast<const uint8_t*>(value.data()),
             static_cast<ossl_ssize_t>(value.size()), -1, 0) == 1;
}

// Returns the serial number of `certificate` if it has the 160-bit network.bs
// form, that is a certificate serial number base in its upper 128 bits.
std::optional<QuicAgentCertificate::SerialNumber> GetSerialNumber(
    X509* certificate) {
  bssl::UniquePtr<BIGNUM> bn(
      ASN1_INTEGER_to_BN(X509_get0_serialNumber(certificate), nullptr));
  if (!bn || BN_is_negative(bn.get()) || BN_num_bits(bn.get()) <= 32 ||
      BN_num_bytes(bn.get()) > QuicAgentCertificate::kSerialNumberSize) {
    return std::nullopt;
  }
  QuicAgentCertificate::SerialNumber serial;
  if (!BN_bn2bin_padded(serial.data(), serial.size(), bn.get())) {
    return std::nullopt;
  }
  return serial;
}

// network.bs "Computing the Certificate Serial Number". The base and counter
// are carried over from the previous certificate's serial number when it has
// that form; otherwise this agent "has never generated an agent certificate".
QuicAgentCertificate::SerialNumber NextSerialNumber(X509* previous) {
  std::optional<QuicAgentCertificate::SerialNumber> serial =
      previous ? GetSerialNumber(previous) : std::nullopt;
  if (!serial) {
    serial.emplace();
    // A random (version 4) UUID as the certificate serial number base. The
    // top bit is cleared so that the DER INTEGER, which must be positive,
    // fits the 20 octets RFC 5280 allows.
    std::array<uint8_t, 16> uuid = GenerateRandomBytes16();
    uuid[0] &= 0x7f;
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    std::copy(uuid.begin(), uuid.end(), serial->begin());
    std::fill(serial->begin() + 16, serial->end(), 0);
  }
  // Increment the 32-bit certificate serial number counter.
  uint32_t counter = 0;
  for (size_t i = 16; i < 20; ++i) {
    counter = (counter << 8) | (*serial)[i];
  }
  ++counter;
  for (size_t i = 20; i > 16; --i) {
    (*serial)[i - 1] = static_cast<uint8_t>(counter);
    counter >>= 8;
  }
  return *serial;
}

bssl::UniquePtr<X509> ParseCertificate(std::string_view der) {
  const uint8_t* data = reinterpret_cast<const uint8_t*>(der.data());
  return bssl::UniquePtr<X509>(d2i_X509(nullptr, &data, der.size()));
}

}  // namespace

// static
std::string QuicAgentCertificate::ComputeAgentHostname(
    const SerialNumber& serial_number,
    std::string_view instance_name,
    std::string_view domain) {
  return base64::Encode(ByteView(serial_number)) + "." +
         EncodeHostnameLabel(instance_name) + "." + EncodeHostnameLabel(domain);
}

bool QuicAgentCertificate::SetIdentity(const Identity& identity,
                                       bool overwrite) {
  if (identity_ && !overwrite) {
    return true;
  }
  identity_ = identity;
  return ApplyIdentity();
}

std::string QuicAgentCertificate::GetCertificateDer() const {
  return certificates_.empty() ? std::string() : certificates_[0];
}

bool QuicAgentCertificate::ApplyIdentity() {
  if (!identity_ || certificates_.empty() || !key_) {
    return false;
  }
  bssl::UniquePtr<X509> current = ParseCertificate(certificates_[0]);
  if (current) {
    std::optional<SerialNumber> serial = GetSerialNumber(current.get());
    if (serial &&
        GetCommonName(X509_get_issuer_name(current.get())) ==
            identity_->model_name &&
        GetCommonName(X509_get_subject_name(current.get())) ==
            ComputeAgentHostname(*serial, identity_->instance_name,
                                 identity_->domain)) {
      return true;
    }
  }

  const SerialNumber serial = NextSerialNumber(current.get());
  const std::string hostname =
      ComputeAgentHostname(serial, identity_->instance_name, identity_->domain);

  // network.bs "Agent Certificates": an X.509 v3, self-signed certificate
  // for the 256-bit ECDSA key, signed with ecdsa_secp256r1_sha256.
  bssl::UniquePtr<X509> certificate(X509_new());
  bssl::UniquePtr<BIGNUM> serial_bn(
      BN_bin2bn(serial.data(), serial.size(), nullptr));
  const std::chrono::seconds now = GetWallTimeSinceUnixEpoch();
  bssl::UniquePtr<ASN1_TIME> not_before(ASN1_TIME_set(nullptr, now.count()));
  bssl::UniquePtr<ASN1_TIME> not_after(
      ASN1_TIME_set(nullptr, (now + kCertificateDuration).count()));
  bssl::UniquePtr<X509_NAME> issuer(X509_NAME_new());
  bssl::UniquePtr<X509_NAME> subject(X509_NAME_new());
  bssl::UniquePtr<ASN1_BIT_STRING> key_usage(ASN1_BIT_STRING_new());
  // KeyUsage bit 0 is digitalSignature.
  constexpr int kDigitalSignatureBit = 0;
  if (!certificate || !serial_bn || !not_before || !not_after || !issuer ||
      !subject || !key_usage ||
      X509_set_version(certificate.get(), X509_VERSION_3) != 1 ||
      !BN_to_ASN1_INTEGER(serial_bn.get(),
                          X509_get_serialNumber(certificate.get())) ||
      X509_set1_notBefore(certificate.get(), not_before.get()) != 1 ||
      X509_set1_notAfter(certificate.get(), not_after.get()) != 1 ||
      // Issuer Name: "CN = The model-name from the agent-info message".
      !AddCommonName(issuer.get(), identity_->model_name) ||
      X509_set_issuer_name(certificate.get(), issuer.get()) != 1 ||
      // Subject Name: "CN = agent hostname".
      !AddCommonName(subject.get(), hostname) ||
      X509_set_subject_name(certificate.get(), subject.get()) != 1 ||
      X509_set_pubkey(certificate.get(), key_.get()) != 1 ||
      // Certificate Key usage: digitalSignature.
      ASN1_BIT_STRING_set_bit(key_usage.get(), kDigitalSignatureBit, 1) != 1 ||
      X509_add1_ext_i2d(certificate.get(), NID_key_usage, key_usage.get(),
                        /*crit=*/1, X509V3_ADD_DEFAULT) != 1 ||
      X509_sign(certificate.get(), key_.get(), EVP_sha256()) <= 0) {
    OSP_LOG_ERROR << "Failed to generate the agent certificate";
    return false;
  }

  uint8_t* der = nullptr;
  const int der_length = i2d_X509(certificate.get(), &der);
  if (der_length <= 0) {
    return false;
  }
  bssl::UniquePtr<uint8_t> der_owner(der);
  std::string der_cert(reinterpret_cast<const char*>(der),
                       static_cast<size_t>(der_length));
  AgentFingerprint fingerprint = ComputeAgentFingerprint(der_cert);
  if (fingerprint.empty()) {
    return false;
  }
  certificates_ = {std::move(der_cert)};
  agent_fingerprint_ = std::move(fingerprint);
  OSP_LOG_INFO << "Agent certificate: issuer CN=\"" << identity_->model_name
               << "\" subject CN=\"" << hostname
               << "\" fp=" << agent_fingerprint_;
  return true;
}

QuicAgentCertificate::QuicAgentCertificate() {
  // Load the certificate and key files if they already exist, otherwise
  // generate new certificate and key files.
  bool result = LoadCredentials();
  if (!result) {
    result = GenerateCredentialsToFile() && LoadCredentials();
    OSP_CHECK(result);
  }
}

QuicAgentCertificate::~QuicAgentCertificate() = default;

// static
AgentFingerprint QuicAgentCertificate::ComputeAgentFingerprint(
    std::string_view der_cert) {
  const uint8_t* data = reinterpret_cast<const uint8_t*>(der_cert.data());
  bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &data, der_cert.size()));
  if (!cert) {
    return {};
  }
  uint8_t* spki = nullptr;
  const int spki_length =
      i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert.get()), &spki);
  if (spki_length <= 0) {
    return {};
  }
  bssl::UniquePtr<uint8_t> spki_owner(spki);
  return base64::Encode(quic::RawSha256(std::string_view(
      reinterpret_cast<const char*>(spki), static_cast<size_t>(spki_length))));
}

bool QuicAgentCertificate::LoadAgentCertificate(std::string_view filename) {
  certificates_.clear();
  agent_fingerprint_.clear();

  // NOTE: There are currently some spec issues about certificates that are
  // still under discussion. Add validations to check if this is a valid OSP
  // agent certificate once all the issues are closed.
  certificates_ = ReadCertificatesFromPemFile(filename);
  if (!certificates_.empty()) {
    agent_fingerprint_ = ComputeAgentFingerprint(certificates_[0]);
    return !agent_fingerprint_.empty();
  } else {
    return false;
  }
}

bool QuicAgentCertificate::LoadPrivateKey(std::string_view filename) {
  key_.reset();
  std::string file_data = ReadEntireFileToString(filename);
  if (file_data.empty()) {
    return false;
  }

  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(const_cast<char*>(file_data.data()),
                                           static_cast<int>(file_data.size())));
  if (!bio) {
    return false;
  }

  key_ = bssl::UniquePtr<EVP_PKEY>(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  return (key_ != nullptr);
}

bool QuicAgentCertificate::RotateAgentCertificate() {
  if (!GenerateCredentialsToFile() || !LoadCredentials()) {
    return false;
  }
  return !identity_ || ApplyIdentity();
}

AgentFingerprint QuicAgentCertificate::GetAgentFingerprint() {
  return agent_fingerprint_;
}

std::unique_ptr<quic::ProofSource>
QuicAgentCertificate::CreateServerProofSource() {
  if (certificates_.empty() || !key_ || agent_fingerprint_.empty()) {
    return nullptr;
  }

  auto chain = quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain>(
      new quic::ProofSource::Chain(certificates_));
  OSP_CHECK(chain) << "Failed to create the quic::ProofSource::Chain.";

  // Keep `key_`: the certificate may be regenerated, see `ApplyIdentity`.
  quic::CertificatePrivateKey key{bssl::UpRef(key_)};
  return quic::ProofSourceX509::Create(std::move(chain), std::move(key));
}

void QuicAgentCertificate::ResetCredentials() {
  agent_fingerprint_.clear();
  certificates_.clear();
  key_.reset();
}

std::unique_ptr<quic::ClientProofSource>
QuicAgentCertificate::CreateClientProofSource(
    std::string_view server_hostname) {
  if (certificates_.empty() || !key_ || agent_fingerprint_.empty()) {
    return nullptr;
  }

  auto chain = quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain>(
      new quic::ProofSource::Chain(certificates_));
  OSP_CHECK(chain) << "Failed to create the quic::ProofSource::Chain.";

  // Keep `key_`: the certificate may be regenerated, see `ApplyIdentity`.
  quic::CertificatePrivateKey key{bssl::UpRef(key_)};
  auto client_proof_source = std::make_unique<quic::DefaultClientProofSource>();
  client_proof_source->AddCertAndKey(
      std::vector<std::string>{std::string{server_hostname}}, std::move(chain),
      std::move(key));
  return client_proof_source;
}

bool QuicAgentCertificate::GenerateCredentialsToFile() {
  bssl::UniquePtr<EVP_PKEY> root_key = GeneratePrivateKey();
  bssl::UniquePtr<X509> root_cert = GenerateRootCert(*root_key);

  FileUniquePtr f(fopen(kPrivateKeyPath, "w"), &fclose);
  if (PEM_write_PrivateKey(f.get(), root_key.get(), nullptr, nullptr, 0, 0,
                           nullptr) != 1) {
    OSP_LOG_ERROR << "Failed to write private key, check permissions?";
    return false;
  }
  OSP_LOG_INFO << "Generated new private key in file: " << kPrivateKeyPath;

  FileUniquePtr cert_file(fopen(kCertificatesPath, "w"), &fclose);
  if (PEM_write_X509(cert_file.get(), root_cert.get()) != 1) {
    OSP_LOG_ERROR << "Failed to write agent certificate, check permissions?";
    return false;
  }
  OSP_LOG_INFO << "Generated new agent certificate in file: "
               << kCertificatesPath;

  return true;
}

bool QuicAgentCertificate::LoadCredentials() {
  bool result = LoadAgentCertificate(kCertificatesPath) &&
                LoadPrivateKey(kPrivateKeyPath);
  if (!result) {
    ResetCredentials();
    return false;
  } else {
    return true;
  }
}

}  // namespace openscreen::osp

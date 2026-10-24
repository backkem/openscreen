// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "util/crypto/spake2.h"

#include <openssl/bn.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/sha.h>

#include <string_view>
#include <utility>

#include "util/osp_logging.h"

namespace openscreen {

namespace {

// RFC 9382 section 4: the compressed SEC1 encodings of M and N for P-256.
constexpr uint8_t kP256M[] = {
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d,
    0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3,
    0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f};
constexpr uint8_t kP256N[] = {
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d,
    0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01,
    0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49};

// Length of a P-256 scalar in bytes.
constexpr size_t kScalarLength = 32;

constexpr std::string_view kConfirmationKeysInfo = "ConfirmationKeys";

// Appends `data` to `transcript`, prefixed by its length as an 8-byte
// little-endian integer (RFC 9382 section 3.3).
void AppendWithLength(ByteView data, std::vector<uint8_t>& transcript) {
  uint64_t length = data.size();
  for (int i = 0; i < 8; ++i) {
    transcript.push_back(static_cast<uint8_t>(length & 0xff));
    length >>= 8;
  }
  transcript.insert(transcript.end(), data.begin(), data.end());
}

std::vector<uint8_t> HashSha256(ByteView data) {
  std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
  SHA256(data.data(), data.size(), digest.data());
  return digest;
}

std::vector<uint8_t> HmacSha256(ByteView key, ByteView data) {
  std::vector<uint8_t> mac(SHA256_DIGEST_LENGTH);
  unsigned int mac_length = 0;
  OSP_CHECK(HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(),
                 mac.data(), &mac_length));
  OSP_CHECK_EQ(mac_length, mac.size());
  return mac;
}

// Deleter for secret BIGNUMs (w, x, y): zeroes them before freeing.
struct BignumClearDeleter {
  void operator()(BIGNUM* bn) const { BN_clear_free(bn); }
};
using SecretBignum = std::unique_ptr<BIGNUM, BignumClearDeleter>;

void Cleanse(std::vector<uint8_t>& secret) {
  if (!secret.empty()) {
    OPENSSL_cleanse(secret.data(), secret.size());
  }
  secret.clear();
}

}  // namespace

struct Spake2::Impl {
  bssl::UniquePtr<EC_GROUP> group;
  bssl::UniquePtr<BN_CTX> ctx;
  SecretBignum w;
  SecretBignum ephemeral;  // x (role A) or y (role B).
  bssl::UniquePtr<EC_POINT> m;
  bssl::UniquePtr<EC_POINT> n;

  std::vector<uint8_t> EncodePoint(const EC_POINT& point) const {
    const size_t length =
        EC_POINT_point2oct(group.get(), &point, POINT_CONVERSION_UNCOMPRESSED,
                           nullptr, 0, ctx.get());
    OSP_CHECK_GT(length, 0u);
    std::vector<uint8_t> out(length);
    OSP_CHECK_EQ(
        EC_POINT_point2oct(group.get(), &point, POINT_CONVERSION_UNCOMPRESSED,
                           out.data(), out.size(), ctx.get()),
        length);
    return out;
  }

  // Returns nullptr if `bytes` is not a valid encoding of a point on the
  // curve, or encodes the point at infinity.
  bssl::UniquePtr<EC_POINT> DecodePoint(ByteView bytes) const {
    bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
    if (!point ||
        !EC_POINT_oct2point(group.get(), point.get(), bytes.data(),
                            bytes.size(), ctx.get()) ||
        EC_POINT_is_at_infinity(group.get(), point.get())) {
      return nullptr;
    }
    return point;
  }
};

// static
ErrorOr<std::unique_ptr<Spake2>> Spake2::Create(const Options& options,
                                                ByteView password) {
  auto impl = std::make_unique<Impl>();
  impl->group.reset(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  impl->ctx.reset(BN_CTX_new());
  impl->w.reset(BN_new());
  impl->ephemeral.reset(BN_new());
  if (!impl->group || !impl->ctx || !impl->w || !impl->ephemeral) {
    return Error(Error::Code::kInitializationFailure);
  }
  const BIGNUM* order = EC_GROUP_get0_order(impl->group.get());

  // w = MHF(pw) mod p, where p is the group order.
  std::vector<uint8_t> digest;
  switch (options.password_hash) {
    case PasswordHash::kSha256:
      digest = HashSha256(password);
      break;
    case PasswordHash::kSha512:
      digest.resize(SHA512_DIGEST_LENGTH);
      SHA512(password.data(), password.size(), digest.data());
      break;
  }
  SecretBignum digest_bn(BN_bin2bn(digest.data(), digest.size(), nullptr));
  Cleanse(digest);
  if (!digest_bn ||
      !BN_nnmod(impl->w.get(), digest_bn.get(), order, impl->ctx.get())) {
    return Error(Error::Code::kInitializationFailure);
  }

  // x or y is chosen uniformly at random in [1, p).
  if (!BN_rand_range_ex(impl->ephemeral.get(), 1, order)) {
    return Error(Error::Code::kInitializationFailure);
  }

  std::unique_ptr<Spake2> spake2(new Spake2(options, std::move(impl)));
  Error error = spake2->Initialize();
  if (!error.ok()) {
    return error;
  }
  return spake2;
}

// static
ErrorOr<std::unique_ptr<Spake2>> Spake2::CreateForTesting(
    const Options& options,
    ByteView w,
    ByteView ephemeral_scalar) {
  auto impl = std::make_unique<Impl>();
  impl->group.reset(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  impl->ctx.reset(BN_CTX_new());
  impl->w = SecretBignum(BN_bin2bn(w.data(), w.size(), nullptr));
  impl->ephemeral = SecretBignum(
      BN_bin2bn(ephemeral_scalar.data(), ephemeral_scalar.size(), nullptr));
  if (!impl->group || !impl->ctx || !impl->w || !impl->ephemeral) {
    return Error(Error::Code::kInitializationFailure);
  }
  std::unique_ptr<Spake2> spake2(new Spake2(options, std::move(impl)));
  Error error = spake2->Initialize();
  if (!error.ok()) {
    return error;
  }
  return spake2;
}

Spake2::Spake2(const Options& options, std::unique_ptr<Impl> impl)
    : options_(options), impl_(std::move(impl)) {}

Spake2::~Spake2() {
  Cleanse(transcript_);
  Cleanse(shared_key_);
  Cleanse(confirmation_key_);
  Cleanse(peer_confirmation_key_);
}

Error Spake2::Initialize() {
  impl_->m = impl_->DecodePoint(kP256M);
  impl_->n = impl_->DecodePoint(kP256N);
  OSP_CHECK(impl_->m);
  OSP_CHECK(impl_->n);

  // pA = x*P + w*M (role A), pB = y*P + w*N (role B).
  const EC_POINT* blinding =
      options_.role == Role::kA ? impl_->m.get() : impl_->n.get();
  bssl::UniquePtr<EC_POINT> share(EC_POINT_new(impl_->group.get()));
  if (!share ||
      !EC_POINT_mul(impl_->group.get(), share.get(), impl_->ephemeral.get(),
                    blinding, impl_->w.get(), impl_->ctx.get())) {
    return Error(Error::Code::kInitializationFailure);
  }
  public_share_ = impl_->EncodePoint(*share);
  return Error::None();
}

Error Spake2::ProcessPeerShare(ByteView peer_share) {
  if (keys_derived_) {
    return Error(Error::Code::kOperationInvalid,
                 "SPAKE2 peer share already processed");
  }
  bssl::UniquePtr<EC_POINT> peer = impl_->DecodePoint(peer_share);
  if (!peer) {
    return Error(Error::Code::kParameterInvalid, "invalid SPAKE2 peer share");
  }

  // K = h*x*(pB - w*N) (role A) or K = h*y*(pA - w*M) (role B). The P-256
  // cofactor h is 1.
  const EC_POINT* peer_blinding =
      options_.role == Role::kA ? impl_->n.get() : impl_->m.get();
  EC_GROUP* group = impl_->group.get();
  BN_CTX* ctx = impl_->ctx.get();
  bssl::UniquePtr<EC_POINT> unblinded(EC_POINT_new(group));
  bssl::UniquePtr<EC_POINT> k(EC_POINT_new(group));
  if (!unblinded || !k ||
      !EC_POINT_mul(group, unblinded.get(), nullptr, peer_blinding,
                    impl_->w.get(), ctx) ||
      !EC_POINT_invert(group, unblinded.get(), ctx) ||
      !EC_POINT_add(group, unblinded.get(), peer.get(), unblinded.get(), ctx) ||
      !EC_POINT_mul(group, k.get(), nullptr, unblinded.get(),
                    impl_->ephemeral.get(), ctx)) {
    return Error(Error::Code::kUnknownError, "SPAKE2 point arithmetic failed");
  }
  if (EC_POINT_is_at_infinity(group, k.get())) {
    return Error(Error::Code::kParameterInvalid, "SPAKE2 K is the identity");
  }

  // TT = len(A) || A || len(B) || B || len(pA) || pA || len(pB) || pB
  //      || len(K) || K || len(w) || w
  const std::vector<uint8_t>& p_a =
      options_.role == Role::kA
          ? public_share_
          : std::vector<uint8_t>(peer_share.begin(), peer_share.end());
  const std::vector<uint8_t>& p_b =
      options_.role == Role::kB
          ? public_share_
          : std::vector<uint8_t>(peer_share.begin(), peer_share.end());
  std::vector<uint8_t> w(kScalarLength);
  OSP_CHECK(BN_bn2bin_padded(w.data(), w.size(), impl_->w.get()));

  transcript_.clear();
  AppendWithLength(options_.identity_a, transcript_);
  AppendWithLength(options_.identity_b, transcript_);
  AppendWithLength(p_a, transcript_);
  AppendWithLength(p_b, transcript_);
  AppendWithLength(impl_->EncodePoint(*k), transcript_);
  AppendWithLength(w, transcript_);

  // Hash(TT) = Ke || Ka.
  std::vector<uint8_t> tt_hash = HashSha256(transcript_);
  Cleanse(w);
  const size_t half = tt_hash.size() / 2;
  shared_key_.assign(tt_hash.begin(), tt_hash.begin() + half);
  std::vector<uint8_t> ka(tt_hash.begin() + half, tt_hash.end());

  // KcA || KcB = KDF(Ka, nil, "ConfirmationKeys" || AAD, L).
  std::vector<uint8_t> info(kConfirmationKeysInfo.begin(),
                            kConfirmationKeysInfo.end());
  info.insert(info.end(), options_.aad.begin(), options_.aad.end());
  std::vector<uint8_t> kc(2 * half);
  const bool hkdf_ok =
      HKDF(kc.data(), kc.size(), EVP_sha256(), ka.data(), ka.size(),
           /*salt=*/nullptr, 0, info.data(), info.size());
  Cleanse(ka);
  Cleanse(tt_hash);
  if (!hkdf_ok) {
    Cleanse(kc);
    return Error(Error::Code::kUnknownError, "SPAKE2 HKDF failed");
  }
  std::vector<uint8_t> kc_a(kc.begin(), kc.begin() + half);
  std::vector<uint8_t> kc_b(kc.begin() + half, kc.end());
  if (options_.role == Role::kA) {
    confirmation_key_ = std::move(kc_a);
    peer_confirmation_key_ = std::move(kc_b);
  } else {
    confirmation_key_ = std::move(kc_b);
    peer_confirmation_key_ = std::move(kc_a);
  }

  Cleanse(kc);

  // cA = MAC(KcA, TT), cB = MAC(KcB, TT).
  confirmation_ = HmacSha256(confirmation_key_, transcript_);
  keys_derived_ = true;
  return Error::None();
}

const std::vector<uint8_t>& Spake2::GetConfirmation() const {
  OSP_CHECK(keys_derived_);
  return confirmation_;
}

Error Spake2::VerifyPeerConfirmation(ByteView peer_confirmation) {
  if (!keys_derived_) {
    return Error(Error::Code::kOperationInvalid,
                 "SPAKE2 peer share not processed yet");
  }
  const std::vector<uint8_t> expected =
      HmacSha256(peer_confirmation_key_, transcript_);
  if (peer_confirmation.size() != expected.size() ||
      CRYPTO_memcmp(peer_confirmation.data(), expected.data(),
                    expected.size()) != 0) {
    return Error(Error::Code::kParameterInvalid,
                 "SPAKE2 key confirmation failed");
  }
  confirmed_ = true;
  return Error::None();
}

const std::vector<uint8_t>& Spake2::shared_key() const {
  OSP_CHECK(confirmed_);
  return shared_key_;
}

}  // namespace openscreen

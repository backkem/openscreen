// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "util/crypto/spake2.h"

#include <cstdint>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "platform/base/span.h"

namespace openscreen {
namespace {

// RFC 9382 Appendix B ("Test Vectors") P-256 vectors, hex with an optional
// "0x" prefix.
struct RfcVector {
  const char* id_a;
  const char* id_b;
  const char* w;
  const char* x;
  const char* y;
  const char* p_a;
  const char* p_b;
  const char* ke;
  const char* c_a;
  const char* c_b;
};

std::vector<uint8_t> HexToBytes(const std::string& hex) {
  std::string clean = hex;
  if (clean.substr(0, 2) == "0x") {
    clean = clean.substr(2);
  }
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i + 1 < clean.size(); i += 2) {
    bytes.push_back(
        static_cast<uint8_t>(std::stoi(clean.substr(i, 2), nullptr, 16)));
  }
  return bytes;
}

std::vector<uint8_t> ToBytes(const std::string& s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

void CheckRfcVector(const RfcVector& v) {
  const std::vector<uint8_t> w = HexToBytes(v.w);
  const std::vector<uint8_t> x = HexToBytes(v.x);
  const std::vector<uint8_t> y = HexToBytes(v.y);
  const std::vector<uint8_t> id_a = ToBytes(v.id_a);
  const std::vector<uint8_t> id_b = ToBytes(v.id_b);

  auto a = Spake2::CreateForTesting(
      {.role = Spake2::Role::kA, .identity_a = id_a, .identity_b = id_b}, w, x);
  ASSERT_TRUE(a.is_value());
  auto b = Spake2::CreateForTesting(
      {.role = Spake2::Role::kB, .identity_a = id_a, .identity_b = id_b}, w, y);
  ASSERT_TRUE(b.is_value());
  Spake2& sa = *a.value();
  Spake2& sb = *b.value();

  EXPECT_EQ(sa.GetPublicShare(), HexToBytes(v.p_a));
  EXPECT_EQ(sb.GetPublicShare(), HexToBytes(v.p_b));

  ASSERT_TRUE(sa.ProcessPeerShare(sb.GetPublicShare()).ok());
  ASSERT_TRUE(sb.ProcessPeerShare(sa.GetPublicShare()).ok());

  EXPECT_EQ(sa.GetConfirmation(), HexToBytes(v.c_a));
  EXPECT_EQ(sb.GetConfirmation(), HexToBytes(v.c_b));

  EXPECT_TRUE(sa.VerifyPeerConfirmation(sb.GetConfirmation()).ok());
  EXPECT_TRUE(sb.VerifyPeerConfirmation(sa.GetConfirmation()).ok());

  const std::vector<uint8_t> ke = HexToBytes(v.ke);
  EXPECT_EQ(sa.shared_key(), ke);
  EXPECT_EQ(sb.shared_key(), ke);
}

}  // namespace

constexpr RfcVector kVector1 = {
    .id_a = "server",
    .id_b = "client",
    .w = "0x2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f",
    .x = "0x43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729",
    .y = "0xdcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be",
    .p_a =
        "0x04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f901"
        "0153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c",
    .p_b =
        "0x0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676d098"
        "57ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7",
    .ke = "0x0e0672dc86f8e45565d338b0540abe69",
    .c_a = "0x58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0",
    .c_b = "0xd3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b",
};

TEST(Spake2Test, Rfc9382P256Vector1) {
  CheckRfcVector(kVector1);
}

constexpr RfcVector kVector2 = {
    .id_a = "",
    .id_b = "client",
    .w = "0x0548d8729f730589e579b0475a582c1608138ddf7054b73b5381c7e883e2efae",
    .x = "0x403abbe3b1b4b9ba17e3032849759d723939a27a27b9d921c500edde18ed654b",
    .y = "0x903023b6598908936ea7c929bd761af6039577a9c3f9581064187c3049d87065",
    .p_a =
        "0x04a897b769e681c62ac1c2357319a3d363f610839c4477720d24cbe32f5fd85f44fb"
        "92ba966578c1b712be6962498834078262caa5b441ecfa9d4a9485720e918a",
    .p_b =
        "0x04e0f816fd1c35e22065d5556215c097e799390d16661c386e0ecc84593974a61b88"
        "1a8c82327687d0501862970c64565560cb5671f696048050ca66ca5f8cc7fc",
    .ke = "0x642f05c473c2cd79909f9a841e2f30a7",
    .c_a = "0x47d29e6666af1b7dd450d571233085d7a9866e4d49d2645e2df975489521232b",
    .c_b = "0x3313c5cefc361d27fb16847a91c2a73b766ffa90a4839122a9b70a2f6bd1d6df",
};

TEST(Spake2Test, Rfc9382P256Vector2) {
  CheckRfcVector(kVector2);
}

constexpr RfcVector kVector3 = {
    .id_a = "server",
    .id_b = "",
    .w = "0x626e0cdc7b14c9db3e52a0b1b3a768c98e37852d5db30febe0497b14eae8c254",
    .x = "0x07adb3db6bc623d3399726bfdbfd3d15a58ea776ab8a308b00392621291f9633",
    .y = "0xb6a4fc8dbb629d4ba51d6f91ed1532cf87adec98f25dd153a75accafafedec16",
    .p_a =
        "0x04f88fb71c99bfffaea370966b7eb99cd4be0ff1a7d335caac4211c4afd855e2e15a"
        "873b298503ad8ba1d9cbb9a392d2ba309b48bfd7879aefd0f2cea6009763b0",
    .p_b =
        "0x040c269d6be017dccb15182ac6bfcd9e2a14de019dd587eaf4bdfd353f031101e7cc"
        "a177f8eb362a6e83e7d5e729c0732e1b528879c086f39ba0f31a9661bd34db",
    .ke = "0x005184ff460da2ce59062c87733c299c",
    .c_a = "0xbc9f9bbe99f26d0b2260e6456e05a86196a3307ec6663a18bf6ac825736533b2",
    .c_b = "0xc2370e1bf813b086dff0d834e74425a06e6390f48f5411900276dcccc5a297ec",
};

TEST(Spake2Test, Rfc9382P256Vector3) {
  CheckRfcVector(kVector3);
}

constexpr RfcVector kVector4 = {
    .id_a = "",
    .id_b = "",
    .w = "0x7bf46c454b4c1b25799527d896508afd5fc62ef4ec59db1efb49113063d70cca",
    .x = "0x8cef65df64bb2d0f83540c53632de911b5b24b3eab6cc74a97609fd659e95473",
    .y = "0xd7a66f64074a84652d8d623a92e20c9675c61cb5b4f6a0063e4648a2fdc02d53",
    .p_a =
        "0x04a65b367a3f613cf9f0654b1b28a1e3a8a40387956c8ba6063e8658563890f46ca1"
        "ef6a676598889fc28de2950ab8120b79a5ef1ea4c9f44bc98f585634b46d66",
    .p_b =
        "0x04589f13218822710d98d8b2123a079041052d9941b9cf88c6617ddb2fcc0494662e"
        "ea8ba6b64692dc318250030c6af045cb738bc81ba35b043c3dcb46adf6f58d",
    .ke = "0xfc6374762ba5cf11f4b2caa08b2cd1b9",
    .c_a = "0xdfb4db8d48ae5a675963ea5e6c19d98d4ea028d8e898dad96ea19a80ade95dca",
    .c_b = "0xd0f0609d1613138d354f7e95f19fb556bf52d751947241e8c7118df5ef0ae175",
};

TEST(Spake2Test, Rfc9382P256Vector4) {
  CheckRfcVector(kVector4);
}

namespace {

Spake2::Options MakeOptions(Spake2::Role role, Spake2::PasswordHash hash) {
  Spake2::Options options;
  options.role = role;
  options.identity_a = ToBytes("server");
  options.identity_b = ToBytes("client");
  options.password_hash = hash;
  return options;
}

void RandomRoundTrip(Spake2::PasswordHash hash) {
  const std::vector<uint8_t> password = ToBytes("123456");
  auto a = Spake2::Create(MakeOptions(Spake2::Role::kA, hash), password);
  ASSERT_TRUE(a.is_value());
  auto b = Spake2::Create(MakeOptions(Spake2::Role::kB, hash), password);
  ASSERT_TRUE(b.is_value());
  Spake2& sa = *a.value();
  Spake2& sb = *b.value();

  ASSERT_TRUE(sa.ProcessPeerShare(sb.GetPublicShare()).ok());
  ASSERT_TRUE(sb.ProcessPeerShare(sa.GetPublicShare()).ok());
  EXPECT_TRUE(sa.VerifyPeerConfirmation(sb.GetConfirmation()).ok());
  EXPECT_TRUE(sb.VerifyPeerConfirmation(sa.GetConfirmation()).ok());

  EXPECT_EQ(sa.shared_key(), sb.shared_key());
  EXPECT_EQ(sa.shared_key().size(), 16u);
}

}  // namespace

TEST(Spake2Test, RandomRoundTripSha512) {
  RandomRoundTrip(Spake2::PasswordHash::kSha512);
}

TEST(Spake2Test, RandomRoundTripSha256) {
  RandomRoundTrip(Spake2::PasswordHash::kSha256);
}

TEST(Spake2Test, WrongPasswordFailsConfirmation) {
  auto a = Spake2::Create(
      MakeOptions(Spake2::Role::kA, Spake2::PasswordHash::kSha256),
      ToBytes("123456"));
  ASSERT_TRUE(a.is_value());
  auto b = Spake2::Create(
      MakeOptions(Spake2::Role::kB, Spake2::PasswordHash::kSha256),
      ToBytes("654321"));
  ASSERT_TRUE(b.is_value());
  Spake2& sa = *a.value();
  Spake2& sb = *b.value();

  ASSERT_TRUE(sa.ProcessPeerShare(sb.GetPublicShare()).ok());
  ASSERT_TRUE(sb.ProcessPeerShare(sa.GetPublicShare()).ok());
  EXPECT_FALSE(sa.VerifyPeerConfirmation(sb.GetConfirmation()).ok());
  EXPECT_FALSE(sb.VerifyPeerConfirmation(sa.GetConfirmation()).ok());
  EXPECT_FALSE(sa.is_confirmed());
  EXPECT_FALSE(sb.is_confirmed());
}

TEST(Spake2Test, RejectsInvalidPeerShare) {
  // 65 bytes with the uncompressed prefix but coordinates not on P-256.
  std::vector<uint8_t> off_curve(65, 0x01);
  off_curve[0] = 0x04;
  auto a = Spake2::Create(
      MakeOptions(Spake2::Role::kA, Spake2::PasswordHash::kSha256),
      ToBytes("123456"));
  ASSERT_TRUE(a.is_value());
  EXPECT_FALSE(a.value()->ProcessPeerShare(off_curve).ok());

  auto b = Spake2::Create(
      MakeOptions(Spake2::Role::kB, Spake2::PasswordHash::kSha256),
      ToBytes("123456"));
  ASSERT_TRUE(b.is_value());
  EXPECT_FALSE(b.value()->ProcessPeerShare(std::vector<uint8_t>()).ok());
}

TEST(Spake2Test, TamperedConfirmationFails) {
  auto a = Spake2::Create(
      MakeOptions(Spake2::Role::kA, Spake2::PasswordHash::kSha256),
      ToBytes("123456"));
  ASSERT_TRUE(a.is_value());
  auto b = Spake2::Create(
      MakeOptions(Spake2::Role::kB, Spake2::PasswordHash::kSha256),
      ToBytes("123456"));
  ASSERT_TRUE(b.is_value());
  Spake2& sa = *a.value();
  Spake2& sb = *b.value();

  ASSERT_TRUE(sa.ProcessPeerShare(sb.GetPublicShare()).ok());
  ASSERT_TRUE(sb.ProcessPeerShare(sa.GetPublicShare()).ok());

  std::vector<uint8_t> tampered = sb.GetConfirmation();
  ASSERT_FALSE(tampered.empty());
  tampered[0] ^= 0x01;
  EXPECT_FALSE(sa.VerifyPeerConfirmation(tampered).ok());
  EXPECT_FALSE(sa.is_confirmed());
}

}  // namespace openscreen

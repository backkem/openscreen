// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/impl/quic/agent_authenticator.h"

#include <charconv>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "osp/impl/quic/quic_client.h"
#include "osp/impl/quic/quic_server.h"
#include "osp/impl/quic/testing/quic_test_support.h"
#include "osp/msgs/osp_messages.h"
#include "osp/public/authentication_config.h"
#include "osp/public/connect_request.h"
#include "platform/test/fake_clock.h"
#include "platform/test/fake_task_runner.h"

namespace openscreen::osp {
namespace {

using ::testing::_;

class ConnectCallback final : public ConnectRequestCallback {
 public:
  void OnConnectSucceed(uint64_t request_id,
                        std::string_view instance_name,
                        uint64_t instance_id) override {
    succeeded_ = true;
    instance_id_ = instance_id;
  }

  void OnConnectFailed(uint64_t request_id,
                       std::string_view instance_name) override {
    failed_ = true;
  }

  bool succeeded() const { return succeeded_; }
  bool failed() const { return failed_; }
  uint64_t instance_id() const { return instance_id_; }

 private:
  bool succeeded_ = false;
  bool failed_ = false;
  uint64_t instance_id_ = 0;
};

class AgentAuthenticatorTest : public ::testing::Test {
 protected:
  void CreateBridge(const AuthenticationConfig* server_override = nullptr) {
    bridge_ = std::make_unique<FakeQuicBridge>(task_runner_, FakeClock::now,
                                               server_override);
    bridge_->CreateNetworkServiceManager(nullptr, nullptr);
  }

  FakeClock fake_clock_{Clock::time_point(std::chrono::milliseconds(1298424))};
  FakeTaskRunner task_runner_{fake_clock_};
  std::unique_ptr<FakeQuicBridge> bridge_;
};

TEST_F(AgentAuthenticatorTest, CanonicalizePsk) {
  EXPECT_EQ(AgentAuthenticator::CanonicalizePsk("0614-8854-8833"),
            "61488548833");
  EXPECT_EQ(AgentAuthenticator::CanonicalizePsk(" 123 456 "), "123456");
  EXPECT_EQ(AgentAuthenticator::CanonicalizePsk("12a4"), "");
  EXPECT_EQ(AgentAuthenticator::CanonicalizePsk("000"), "");
}

TEST_F(AgentAuthenticatorTest, FormatPskForDisplay) {
  // Example from network.bs Appendix B.
  EXPECT_EQ(AgentAuthenticator::FormatPskForDisplay("61488548833"),
            "0614-8854-8833");
  EXPECT_EQ(AgentAuthenticator::FormatPskForDisplay("123456"), "123-456");
  EXPECT_EQ(AgentAuthenticator::FormatPskForDisplay("12345"), "012-345");
}

TEST_F(AgentAuthenticatorTest, GeneratePsk) {
  for (int i = 0; i < 50; ++i) {
    const std::string psk = AgentAuthenticator::GeneratePsk(20);
    ASSERT_FALSE(psk.empty());
    for (char c : psk) {
      ASSERT_TRUE(c >= '0' && c <= '9') << psk;
    }
    uint64_t value = 0;
    auto [end, ec] =
        std::from_chars(psk.data(), psk.data() + psk.size(), value);
    ASSERT_EQ(ec, std::errc());
    ASSERT_EQ(end, psk.data() + psk.size());
    EXPECT_LT(value, uint64_t{1} << 20);
  }

  const std::string long_psk = AgentAuthenticator::GeneratePsk(60);
  uint64_t value = 0;
  auto [end, ec] = std::from_chars(long_psk.data(),
                                   long_psk.data() + long_psk.size(), value);
  ASSERT_EQ(ec, std::errc());
  EXPECT_LT(value, uint64_t{1} << 60);
}

TEST_F(AgentAuthenticatorTest, IsNetworkPhaseMessage) {
  EXPECT_TRUE(AgentAuthenticator::IsNetworkPhaseMessage(
      msgs::Type::kAuthSpake2Handshake));
  EXPECT_TRUE(
      AgentAuthenticator::IsNetworkPhaseMessage(msgs::Type::kAgentInfoRequest));
  EXPECT_FALSE(AgentAuthenticator::IsNetworkPhaseMessage(
      msgs::Type::kPresentationUrlAvailabilityRequest));
}

TEST_F(AgentAuthenticatorTest, ConnectAuthenticatesBothSides) {
  CreateBridge();
  QuicClient* client = bridge_->GetQuicClient();

  ConnectCallback callback;
  ConnectRequest request;
  ASSERT_TRUE(client->Connect(bridge_->kInstanceName, request, &callback));
  ASSERT_TRUE(request);

  bridge_->RunTasksUntilIdle();
  ASSERT_TRUE(callback.succeeded());
  EXPECT_FALSE(callback.failed());

  EXPECT_TRUE(client->IsAuthenticated(callback.instance_id()));
  // The server side uses the first instance ID.
  EXPECT_TRUE(bridge_->GetQuicServer()->IsAuthenticated(1));
}

TEST_F(AgentAuthenticatorTest, WrongPskFailsConnect) {
  AuthenticationConfig server_auth;
  server_auth.psk = "654321";  // The client uses the fixture PSK "123456".
  server_auth.spake2_suite = AuthenticationConfig::Spake2Suite::kP256;
  CreateBridge(&server_auth);
  QuicClient* client = bridge_->GetQuicClient();

  ConnectCallback callback;
  ConnectRequest request;
  ASSERT_TRUE(client->Connect(bridge_->kInstanceName, request, &callback));

  bridge_->RunTasksUntilIdle();
  EXPECT_TRUE(callback.failed());
  EXPECT_FALSE(callback.succeeded());
  EXPECT_FALSE(bridge_->GetQuicServer()->IsAuthenticated(1));
}

TEST_F(AgentAuthenticatorTest, StalledAuthenticationTimesOut) {
  // NON-SPEC: the server skips authentication, so it never presents a PSK and
  // ignores handshakes. The client, the PSK consumer, waits for the presenter
  // until its authentication timeout.
  AuthenticationConfig server_auth;
  server_auth.enabled = false;
  CreateBridge(&server_auth);
  QuicClient* client = bridge_->GetQuicClient();

  ConnectCallback callback;
  ConnectRequest request;
  ASSERT_TRUE(client->Connect(bridge_->kInstanceName, request, &callback));
  bridge_->RunTasksUntilIdle();
  EXPECT_FALSE(callback.succeeded());
  EXPECT_FALSE(callback.failed());

  const auto timeout = AuthenticationConfig().timeout;
  fake_clock_.Advance(timeout - std::chrono::seconds(1));
  bridge_->RunTasksUntilIdle();
  EXPECT_FALSE(callback.failed());

  // The connection is closed when the alarm fires, so only run the task
  // runner: the fake bridge cannot pump packets of a closed connection.
  fake_clock_.Advance(std::chrono::seconds(2));
  task_runner_.RunTasksUntilIdle();
  EXPECT_TRUE(callback.failed());
  EXPECT_FALSE(callback.succeeded());
}

}  // namespace
}  // namespace openscreen::osp

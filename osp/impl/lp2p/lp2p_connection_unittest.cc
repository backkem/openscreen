// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/public/lp2p/lp2p_connection.h"

#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "osp/impl/quic/testing/quic_test_support.h"
#include "osp/public/lp2p/lp2p_data_channel.h"
#include "osp/public/lp2p/lp2p_receiver.h"
#include "osp/public/lp2p/lp2p_request.h"
#include "platform/test/fake_clock.h"
#include "platform/test/fake_task_runner.h"

namespace openscreen::osp {

using ::testing::_;
using ::testing::ElementsAreArray;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::StrictMock;

namespace {

class MockReceiverDelegate : public Lp2pReceiver::Delegate {
 public:
  MOCK_METHOD(void, OnConnectionMock, (Lp2pConnection*));

  // Keeps the connections unless `drop_connections` is set.
  void OnConnection(std::unique_ptr<Lp2pConnection> connection) override {
    OnConnectionMock(connection.get());
    if (!drop_connections) {
      connections.push_back(std::move(connection));
    }
  }

  bool drop_connections = false;
  std::vector<std::unique_ptr<Lp2pConnection>> connections;
};

class MockRequestDelegate : public Lp2pRequest::Delegate {
 public:
  void OnConnection(std::unique_ptr<Lp2pConnection> c) override {
    connection = std::move(c);
  }
  MOCK_METHOD(void, OnError, (const Error&), (override));

  std::unique_ptr<Lp2pConnection> connection;
};

class MockConnectionDelegate : public Lp2pConnection::Delegate {
 public:
  void OnDataChannel(std::unique_ptr<Lp2pDataChannel> channel) override {
    channel->SetDelegate(channel_delegate);
    channels.push_back(std::move(channel));
  }

  Lp2pDataChannel::Delegate* channel_delegate = nullptr;
  std::vector<std::unique_ptr<Lp2pDataChannel>> channels;
};

class MockChannelDelegate : public Lp2pDataChannel::Delegate {
 public:
  MOCK_METHOD(void, OnOpen, (Lp2pDataChannel&), (override));
  MOCK_METHOD(void,
              OnMessage,
              (Lp2pDataChannel&, Lp2pDataEncoding, ByteView),
              (override));
  MOCK_METHOD(void, OnClose, (Lp2pDataChannel&), (override));
};

std::string ToString(ByteView bytes) {
  return std::string(bytes.begin(), bytes.end());
}

}  // namespace

class Lp2pConnectionTest : public ::testing::Test {
 public:
  Lp2pConnectionTest()
      : fake_clock_(Clock::time_point(std::chrono::milliseconds(1298424))),
        task_runner_(fake_clock_),
        quic_bridge_(task_runner_, FakeClock::now) {}

 protected:
  void SetUp() override {
    quic_bridge_.CreateNetworkServiceManager(nullptr, nullptr);
  }

  // Creates the receiver and the request, and connects them.
  void Connect() {
    receiver_ = std::make_unique<Lp2pReceiver>(
        *quic_bridge_.GetQuicServer(), task_runner_, receiver_delegate_);
    request_ = std::make_unique<Lp2pRequest>(*quic_bridge_.GetQuicClient(),
                                             task_runner_);
    ON_CALL(quic_bridge_.mock_server_observer(), OnIncomingConnectionMock(_))
        .WillByDefault([this](std::unique_ptr<ProtocolConnection>& stream) {
          receiver_->OnIncomingStream(std::move(stream));
        });
    ON_CALL(quic_bridge_.mock_client_observer(), OnIncomingConnectionMock(_))
        .WillByDefault([this](std::unique_ptr<ProtocolConnection>& stream) {
          request_->OnIncomingStream(std::move(stream));
        });
    ON_CALL(receiver_delegate_, OnConnectionMock(_))
        .WillByDefault([this](Lp2pConnection* connection) {
          connection->SetDelegate(&receiver_connection_delegate_);
        });

    EXPECT_TRUE(
        request_->Start(quic_bridge_.kInstanceName, request_delegate_).ok());
    quic_bridge_.RunTasksUntilIdle();
    ASSERT_TRUE(request_delegate_.connection);
    EXPECT_EQ(quic_bridge_.kInstanceName,
              request_delegate_.connection->instance_name());
    request_delegate_.connection->SetDelegate(&request_connection_delegate_);
  }

  // Opens a data channel from the requesting side and runs until the
  // receiving side has it.
  std::unique_ptr<Lp2pDataChannel> OpenChannel(
      const Lp2pDataChannelInit& init) {
    ErrorOr<std::unique_ptr<Lp2pDataChannel>> channel =
        request_delegate_.connection->CreateDataChannel(init,
                                                        &request_channel_);
    EXPECT_TRUE(channel.is_value());
    if (channel.is_error()) {
      return nullptr;
    }
    EXPECT_EQ(Lp2pDataChannel::State::kConnecting, channel.value()->state());
    quic_bridge_.RunTasksUntilIdle();
    return std::move(channel.value());
  }

  FakeClock fake_clock_;
  FakeTaskRunner task_runner_;
  FakeQuicBridge quic_bridge_;

  NiceMock<MockReceiverDelegate> receiver_delegate_;
  MockRequestDelegate request_delegate_;
  MockConnectionDelegate receiver_connection_delegate_;
  MockConnectionDelegate request_connection_delegate_;
  NiceMock<MockChannelDelegate> receiver_channel_;
  NiceMock<MockChannelDelegate> request_channel_;
  std::unique_ptr<Lp2pReceiver> receiver_;
  std::unique_ptr<Lp2pRequest> request_;
};

TEST_F(Lp2pConnectionTest, OpenChannelAndExchangeFrames) {
  receiver_connection_delegate_.channel_delegate = &receiver_channel_;
  ASSERT_NO_FATAL_FAILURE(Connect());

  EXPECT_CALL(receiver_delegate_, OnConnectionMock(_));
  EXPECT_CALL(request_channel_, OnOpen(_));
  std::unique_ptr<Lp2pDataChannel> channel =
      OpenChannel({.label = "chat", .protocol = "text", .id = 7});
  ASSERT_TRUE(channel);
  EXPECT_EQ(Lp2pDataChannel::State::kOpen, channel->state());

  ASSERT_EQ(1u, receiver_connection_delegate_.channels.size());
  Lp2pDataChannel& remote = *receiver_connection_delegate_.channels[0];
  EXPECT_EQ(7u, remote.id());
  EXPECT_EQ("chat", remote.label());
  EXPECT_EQ("text", remote.protocol());
  EXPECT_EQ(Lp2pDataChannel::State::kOpen, remote.state());

  std::string received;
  EXPECT_CALL(receiver_channel_, OnMessage(_, Lp2pDataEncoding::kString, _))
      .WillOnce(
          [&received](Lp2pDataChannel&, Lp2pDataEncoding, ByteView payload) {
            received = ToString(payload);
          });
  EXPECT_TRUE(channel->Send("hello").ok());
  quic_bridge_.RunTasksUntilIdle();
  EXPECT_EQ("hello", received);

  const std::vector<uint8_t> data = {0, 1, 2, 255};
  std::vector<uint8_t> received_data;
  EXPECT_CALL(request_channel_, OnMessage(_, Lp2pDataEncoding::kArrayBuffer, _))
      .WillOnce([&received_data](Lp2pDataChannel&, Lp2pDataEncoding,
                                 ByteView payload) {
        received_data.assign(payload.begin(), payload.end());
      });
  EXPECT_TRUE(remote.Send(data, Lp2pDataEncoding::kArrayBuffer).ok());
  quic_bridge_.RunTasksUntilIdle();
  EXPECT_THAT(received_data, ElementsAreArray(data));
}

TEST_F(Lp2pConnectionTest, ReceiverOpensChannelOnExistingConnection) {
  receiver_connection_delegate_.channel_delegate = &receiver_channel_;
  request_connection_delegate_.channel_delegate = &request_channel_;
  ASSERT_NO_FATAL_FAILURE(Connect());
  std::unique_ptr<Lp2pDataChannel> first = OpenChannel({.label = "first"});
  ASSERT_EQ(1u, receiver_delegate_.connections.size());

  NiceMock<MockChannelDelegate> opener;
  EXPECT_CALL(opener, OnOpen(_));
  ErrorOr<std::unique_ptr<Lp2pDataChannel>> channel =
      receiver_delegate_.connections[0]->CreateDataChannel({.label = "back"},
                                                           &opener);
  ASSERT_TRUE(channel.is_value());
  quic_bridge_.RunTasksUntilIdle();
  EXPECT_EQ(Lp2pDataChannel::State::kOpen, channel.value()->state());
  ASSERT_EQ(1u, request_connection_delegate_.channels.size());
  EXPECT_EQ("back", request_connection_delegate_.channels[0]->label());
}

TEST_F(Lp2pConnectionTest, PicksUnusedChannelIds) {
  ASSERT_NO_FATAL_FAILURE(Connect());
  std::unique_ptr<Lp2pDataChannel> first = OpenChannel({});
  std::unique_ptr<Lp2pDataChannel> second = OpenChannel({});
  ASSERT_TRUE(first && second);
  EXPECT_EQ(0u, first->id());
  EXPECT_EQ(1u, second->id());

  EXPECT_TRUE(request_delegate_.connection
                  ->CreateDataChannel({.id = kMaxLp2pDataChannelId + 1},
                                      &request_channel_)
                  .is_error());
}

TEST_F(Lp2pConnectionTest, RejectedChannelCloses) {
  receiver_delegate_.drop_connections = true;
  ASSERT_NO_FATAL_FAILURE(Connect());

  EXPECT_CALL(request_channel_, OnOpen(_)).Times(0);
  EXPECT_CALL(request_channel_, OnClose(_));
  std::unique_ptr<Lp2pDataChannel> channel = OpenChannel({.label = "chat"});
  ASSERT_TRUE(channel);
  EXPECT_EQ(Lp2pDataChannel::State::kClosed, channel->state());
  EXPECT_FALSE(channel->Send("hello").ok());
}

TEST_F(Lp2pConnectionTest, CloseStopsChannel) {
  // The fake QUIC streams do not report closes to the peer, so this covers
  // the closing side only.
  receiver_connection_delegate_.channel_delegate = &receiver_channel_;
  ASSERT_NO_FATAL_FAILURE(Connect());
  std::unique_ptr<Lp2pDataChannel> channel = OpenChannel({.label = "chat"});
  ASSERT_TRUE(channel);
  ASSERT_EQ(1u, receiver_connection_delegate_.channels.size());

  EXPECT_CALL(request_channel_, OnClose(_)).Times(0);
  EXPECT_CALL(request_channel_, OnMessage(_, _, _)).Times(0);
  channel->Close();
  EXPECT_EQ(Lp2pDataChannel::State::kClosed, channel->state());
  EXPECT_FALSE(channel->Send("hello").ok());

  receiver_connection_delegate_.channels[0]->Send("dropped");
  quic_bridge_.RunTasksUntilIdle();
}

}  // namespace openscreen::osp

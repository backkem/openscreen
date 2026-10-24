// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstring>

#include "gtest/gtest.h"
#include "osp/msgs/osp_messages.h"

using openscreen::msgs::CborEncodeBuffer;
using openscreen::msgs::HttpHeader;
using openscreen::msgs::PresentationConnectionCloseEvent;
using openscreen::msgs::PresentationConnectionMessage;
using openscreen::msgs::PresentationStartRequest;
using openscreen::msgs::PresentationUrlAvailabilityRequest;

namespace openscreen::osp {

TEST(PresentationMessagesTest, EncodeRequestOneUrl) {
  uint8_t buffer[256];
  std::vector<std::string> urls = {"https://example.com/receiver.html"};
  int64_t bytes_out = EncodePresentationUrlAvailabilityRequest(
      PresentationUrlAvailabilityRequest{7, urls}, buffer, sizeof(buffer));
  ASSERT_LE(bytes_out, static_cast<int64_t>(sizeof(buffer)));
  ASSERT_GT(bytes_out, 0);

  PresentationUrlAvailabilityRequest decoded_request;
  int64_t bytes_read = DecodePresentationUrlAvailabilityRequest(
      buffer, bytes_out, decoded_request);
  ASSERT_EQ(bytes_read, bytes_out);
  EXPECT_EQ(7u, decoded_request.request_id);
  EXPECT_EQ(urls, decoded_request.urls);
}

TEST(PresentationMessagesTest, EncodeRequestMultipleUrls) {
  uint8_t buffer[256];
  std::vector<std::string> urls{"https://example.com/receiver.html",
                                "https://openscreen.org/demo_receiver.html",
                                "https://turt.le/asdfXCV"};
  int64_t bytes_out = EncodePresentationUrlAvailabilityRequest(
      PresentationUrlAvailabilityRequest{7, urls}, buffer, sizeof(buffer));
  ASSERT_LE(bytes_out, static_cast<int64_t>(sizeof(buffer)));
  ASSERT_GT(bytes_out, 0);

  PresentationUrlAvailabilityRequest decoded_request;
  int64_t bytes_read = DecodePresentationUrlAvailabilityRequest(
      buffer, bytes_out, decoded_request);
  ASSERT_EQ(bytes_read, bytes_out);
  EXPECT_EQ(7u, decoded_request.request_id);
  EXPECT_EQ(urls, decoded_request.urls);
}

TEST(PresentationMessagesTest, EncodeWouldOverflow) {
  uint8_t buffer[40];
  std::vector<std::string> urls = {"https://example.com/receiver.html"};
  int64_t bytes_out = EncodePresentationUrlAvailabilityRequest(
      PresentationUrlAvailabilityRequest{7, urls}, buffer, sizeof(buffer));
  ASSERT_GT(bytes_out, static_cast<int64_t>(sizeof(buffer)));
}

// TODO(btolsch): Expand invalid utf8 testing to good/bad files and fuzzing.
TEST(PresentationMessagesTest, EncodeInvalidUtf8) {
  uint8_t buffer[256];
  std::vector<std::string> urls = {"\xc0"};
  int64_t bytes_out = EncodePresentationUrlAvailabilityRequest(
      PresentationUrlAvailabilityRequest{7, urls}, buffer, sizeof(buffer));
  ASSERT_GT(0, bytes_out);
}

TEST(PresentationMessagesTest, DecodeInvalidUtf8) {
  uint8_t buffer[256];
  std::vector<std::string> urls = {"https://example.com/receiver.html"};
  int64_t bytes_out = EncodePresentationUrlAvailabilityRequest(
      PresentationUrlAvailabilityRequest{7, urls}, buffer, sizeof(buffer));
  ASSERT_LE(bytes_out, static_cast<int64_t>(sizeof(buffer)));
  ASSERT_GT(bytes_out, 0);
  // Manually change a character in the url string to be non-utf8.
  buffer[30] = 0xc0;

  PresentationUrlAvailabilityRequest decoded_request;
  int64_t bytes_read = DecodePresentationUrlAvailabilityRequest(
      buffer, bytes_out, decoded_request);
  ASSERT_GT(0, bytes_read);
}

TEST(PresentationMessagesTest, InitiationRequest) {
  uint8_t buffer[256];
  const std::string kPresentationId = "lksdjfloiqwerlkjasdlfq";
  const std::string kPresentationUrl = "https://example.com/receiver.html";
  std::vector<HttpHeader> headers;
  int64_t bytes_out = EncodePresentationStartRequest(
      PresentationStartRequest{13, kPresentationId, kPresentationUrl, headers},
      buffer, sizeof(buffer));
  ASSERT_LE(bytes_out, static_cast<int64_t>(sizeof(buffer)));
  ASSERT_GT(bytes_out, 0);

  PresentationStartRequest decoded_request;
  int64_t bytes_read =
      DecodePresentationStartRequest(buffer, bytes_out, decoded_request);
  ASSERT_EQ(bytes_read, bytes_out);
  EXPECT_EQ(13u, decoded_request.request_id);
  EXPECT_EQ(kPresentationId, decoded_request.presentation_id);
  EXPECT_EQ(kPresentationUrl, decoded_request.url);
  EXPECT_EQ(0, (int)decoded_request.headers.size());
}

TEST(PresentationMessagesTest, InitiationRequestWithoutOptional) {
  uint8_t buffer[256];
  const std::string kPresentationId = "lksdjfloiqwerlkjasdlfq";
  const std::string kPresentationUrl = "https://example.com/receiver.html";
  std::vector<HttpHeader> headers;
  int64_t bytes_out = EncodePresentationStartRequest(
      PresentationStartRequest{13, kPresentationId, kPresentationUrl, headers},
      buffer, sizeof(buffer));
  ASSERT_LE(bytes_out, static_cast<int64_t>(sizeof(buffer)));
  ASSERT_GT(bytes_out, 0);

  PresentationStartRequest decoded_request;
  int64_t bytes_read =
      DecodePresentationStartRequest(buffer, bytes_out, decoded_request);
  ASSERT_EQ(bytes_read, bytes_out);
  EXPECT_EQ(13u, decoded_request.request_id);
  EXPECT_EQ(kPresentationId, decoded_request.presentation_id);
  EXPECT_EQ(kPresentationUrl, decoded_request.url);
  EXPECT_EQ(0, (int)decoded_request.headers.size());
}

TEST(PresentationMessagesTest, EncodeConnectionMessageString) {
  uint8_t buffer[256];
  PresentationConnectionMessage message;
  message.connection_id = 1234;
  message.message.which =
      PresentationConnectionMessage::Message::Which::kString;
  new (&message.message.str) std::string("test message as a string");
  int64_t bytes_out =
      EncodePresentationConnectionMessage(message, buffer, sizeof(buffer));
  ASSERT_LE(bytes_out, static_cast<int64_t>(sizeof(buffer)));
  ASSERT_GT(bytes_out, 0);

  PresentationConnectionMessage decoded_message;
  int64_t bytes_read =
      DecodePresentationConnectionMessage(buffer, bytes_out, decoded_message);
  ASSERT_GT(bytes_read, 0);
  EXPECT_EQ(bytes_read, bytes_out);
  EXPECT_EQ(message.connection_id, decoded_message.connection_id);
  ASSERT_EQ(message.message.which, decoded_message.message.which);
  EXPECT_EQ(message.message.str, decoded_message.message.str);
}

TEST(PresentationMessagesTest, EncodeConnectionMessageBytes) {
  uint8_t buffer[256];
  PresentationConnectionMessage message;
  message.connection_id = 1234;
  message.message.which = PresentationConnectionMessage::Message::Which::kBytes;
  new (&message.message.bytes)
      std::vector<uint8_t>{0, 1, 2, 3, 255, 254, 253, 86, 71, 0, 0, 1, 0, 2};
  int64_t bytes_out =
      EncodePresentationConnectionMessage(message, buffer, sizeof(buffer));
  ASSERT_LE(bytes_out, static_cast<int64_t>(sizeof(buffer)));
  ASSERT_GT(bytes_out, 0);

  PresentationConnectionMessage decoded_message;
  int64_t bytes_read =
      DecodePresentationConnectionMessage(buffer, bytes_out, decoded_message);
  ASSERT_GT(bytes_read, 0);
  EXPECT_EQ(bytes_read, bytes_out);
  EXPECT_EQ(message.connection_id, decoded_message.connection_id);
  ASSERT_EQ(message.message.which, decoded_message.message.which);
  EXPECT_EQ(message.message.bytes, decoded_message.message.bytes);
}

TEST(PresentationMessagesTest, CborEncodeBufferSmall) {
  std::vector<std::string> urls = {"https://example.com/receiver.html"};
  PresentationUrlAvailabilityRequest request{7, urls};
  CborEncodeBuffer buffer;
  ASSERT_TRUE(EncodePresentationUrlAvailabilityRequest(request, &buffer));
  EXPECT_LT(buffer.size(), CborEncodeBuffer::kDefaultInitialEncodeBufferSize);

  PresentationUrlAvailabilityRequest decoded_request;
  int64_t bytes_read = DecodePresentationUrlAvailabilityRequest(
      buffer.data() + 1, buffer.size() - 1, decoded_request);
  EXPECT_EQ(static_cast<size_t>(bytes_read), buffer.size() - 1);
  EXPECT_EQ(request.request_id, decoded_request.request_id);
  EXPECT_EQ(request.urls, decoded_request.urls);
}

TEST(PresentationMessagesTest, CborEncodeBufferMedium) {
  std::string url = "https://example.com/receiver.html";
  std::vector<std::string> urls{};
  for (int i = 0; i < 100; ++i) {
    urls.push_back(url);
  }
  PresentationUrlAvailabilityRequest request{7, urls};
  CborEncodeBuffer buffer;
  ASSERT_TRUE(EncodePresentationUrlAvailabilityRequest(request, &buffer));
  EXPECT_GT(buffer.size(), CborEncodeBuffer::kDefaultInitialEncodeBufferSize);

  PresentationUrlAvailabilityRequest decoded_request;
  int64_t bytes_read = DecodePresentationUrlAvailabilityRequest(
      buffer.data() + 1, buffer.size() - 1, decoded_request);
  ASSERT_GT(bytes_read, 0);
  EXPECT_EQ(static_cast<size_t>(bytes_read), buffer.size() - 1);
  EXPECT_EQ(request.request_id, decoded_request.request_id);
  EXPECT_EQ(request.urls, decoded_request.urls);
}

TEST(PresentationMessagesTest, CborEncodeBufferTooLarge) {
  std::vector<std::string> urls = {"https://example.com/receiver.html"};
  PresentationUrlAvailabilityRequest request{7, urls};
  CborEncodeBuffer buffer{10, 30};
  ASSERT_FALSE(EncodePresentationUrlAvailabilityRequest(request, &buffer));
}

TEST(PresentationMessagesTest, EncodePresentationConnectionCloseEvent) {
  uint8_t buffer[256];
  PresentationConnectionCloseEvent event = {
      .connection_id = 1,
      .reason =
          msgs::PresentationConnectionCloseEvent_reason::kCloseMethodCalled,
      .connection_count = 1};
  int64_t bytes_out =
      EncodePresentationConnectionCloseEvent(event, buffer, sizeof(buffer));
  ASSERT_LE(bytes_out, static_cast<int64_t>(sizeof(buffer)));
  ASSERT_GT(bytes_out, 0);

  PresentationConnectionCloseEvent decoded_event;
  int64_t bytes_read =
      DecodePresentationConnectionCloseEvent(buffer, bytes_out, decoded_event);
  ASSERT_EQ(bytes_read, bytes_out);
  EXPECT_EQ(1u, decoded_event.connection_id);
  EXPECT_EQ(1u, decoded_event.connection_count);

  PresentationConnectionCloseEvent event_with_message = {
      .connection_id = 2,
      .reason =
          msgs::PresentationConnectionCloseEvent_reason::kCloseMethodCalled,
      .error_message = "test message",
      .connection_count = 2};
  bytes_out = EncodePresentationConnectionCloseEvent(event_with_message, buffer,
                                                     sizeof(buffer));
  ASSERT_LE(bytes_out, static_cast<int64_t>(sizeof(buffer)));
  ASSERT_GT(bytes_out, 0);

  PresentationConnectionCloseEvent decoded_event_with_message;
  bytes_read = DecodePresentationConnectionCloseEvent(
      buffer, bytes_out, decoded_event_with_message);
  ASSERT_EQ(bytes_read, bytes_out);
  EXPECT_EQ(2u, decoded_event_with_message.connection_id);
  EXPECT_EQ(2u, decoded_event_with_message.connection_count);
  EXPECT_EQ("test message", decoded_event_with_message.error_message);

  // application_messages.cddl: "? 2: text ; error-message" and
  // "3: uint ; connection-count".
  const uint8_t kExpected[] = {0xa4, 0x00, 0x02, 0x01, 0x01, 0x02, 0x6c,
                               't',  'e',  's',  't',  ' ',  'm',  'e',
                               's',  's',  'a',  'g',  'e',  0x03, 0x02};
  ASSERT_EQ(bytes_out, static_cast<int64_t>(sizeof(kExpected)));
  EXPECT_EQ(0, memcmp(kExpected, buffer, sizeof(kExpected)));
}

// remote-playback-state "supports" uses keys 0 to 4, and epoch, duration and
// resolution may be null, which decodes like an absent member.
TEST(RemotePlaybackMessagesTest, DecodeRemotePlaybackStateEvent) {
  const uint8_t kEvent[] = {
      0xa2, 0x00, 0x07,        // remote-playback-id: 7
      0x01, 0xa4,              // state: map(4)
      0x00, 0xa5,              // supports: map(5)
      0x00, 0xf5, 0x01, 0xf4,  // rate: true, preload: false
      0x02, 0xf5, 0x03, 0xf4,  // poster: true, added-text-track: false
      0x04, 0xf5,              // added-cues: true
      0x05, 0xf6,              // epoch: null
      0x06, 0xf6,              // duration: null
      0x12, 0xf6,              // resolution: null
  };
  msgs::RemotePlaybackStateEvent event;
  ASSERT_EQ(
      static_cast<int64_t>(sizeof(kEvent)),
      msgs::DecodeRemotePlaybackStateEvent(kEvent, sizeof(kEvent), event));
  EXPECT_EQ(7u, event.remote_playback_id);
  ASSERT_TRUE(event.state.supports);
  EXPECT_TRUE(event.state.supports->rate);
  EXPECT_FALSE(event.state.supports->preload);
  EXPECT_TRUE(event.state.supports->poster);
  EXPECT_FALSE(event.state.supports->added_text_track);
  EXPECT_TRUE(event.state.supports->added_cues);
  EXPECT_FALSE(event.state.epoch);
  EXPECT_FALSE(event.state.duration);
  EXPECT_FALSE(event.state.resolution);

  // A non-null value still decodes.
  const uint8_t kEventWithEpoch[] = {0xa2, 0x00, 0x07, 0x01,
                                     0xa1, 0x05, 0x18, 0x2a};
  ASSERT_EQ(static_cast<int64_t>(sizeof(kEventWithEpoch)),
            msgs::DecodeRemotePlaybackStateEvent(
                kEventWithEpoch, sizeof(kEventWithEpoch), event));
  ASSERT_TRUE(event.state.epoch);
  EXPECT_EQ(42, *event.state.epoch);
}

// The Local Peer-to-Peer data channel extension messages, with the bytes the
// Go implementation (go-lp2p) encodes them as.
TEST(Lp2pMessagesTest, DataChannelOpenRequest) {
  const uint8_t kRequest[] = {
      0xa4,                            // map(4)
      0x00, 0x01,                      // request-id: 1
      0x01, 0x02,                      // channel-id: 2
      0x02, 0x64, 'c', 'h', 'a', 't',  // label: "chat"
      0x03, 0x60,                      // protocol: ""
  };
  uint8_t buffer[64];
  const msgs::DataChannelOpenRequest request = {
      .request_id = 1, .channel_id = 2, .label = "chat", .protocol = ""};
  const int64_t bytes_out =
      msgs::EncodeDataChannelOpenRequest(request, buffer, sizeof(buffer));
  ASSERT_EQ(static_cast<int64_t>(sizeof(kRequest)), bytes_out);
  EXPECT_EQ(0, memcmp(kRequest, buffer, sizeof(kRequest)));

  msgs::DataChannelOpenRequest decoded;
  ASSERT_EQ(
      static_cast<int64_t>(sizeof(kRequest)),
      msgs::DecodeDataChannelOpenRequest(kRequest, sizeof(kRequest), decoded));
  EXPECT_EQ(request, decoded);
}

TEST(Lp2pMessagesTest, DataChannelOpenResponse) {
  const uint8_t kResponse[] = {
      0xa2,        // map(2)
      0x00, 0x01,  // request-id: 1
      0x01, 0x01,  // result: success
  };
  uint8_t buffer[16];
  const msgs::DataChannelOpenResponse response = {
      .request_id = 1,
      .result = msgs::DataChannelOpenResponse_result::kSuccess};
  const int64_t bytes_out =
      msgs::EncodeDataChannelOpenResponse(response, buffer, sizeof(buffer));
  ASSERT_EQ(static_cast<int64_t>(sizeof(kResponse)), bytes_out);
  EXPECT_EQ(0, memcmp(kResponse, buffer, sizeof(kResponse)));

  msgs::DataChannelOpenResponse decoded;
  ASSERT_EQ(static_cast<int64_t>(sizeof(kResponse)),
            msgs::DecodeDataChannelOpenResponse(kResponse, sizeof(kResponse),
                                                decoded));
  EXPECT_EQ(response, decoded);
}

TEST(Lp2pMessagesTest, DataFrame) {
  const uint8_t kFrame[] = {
      0xa2,                  // map(2)
      0x00, 0x01,            // encoding-id: string
      0x04, 0x42, 'h', 'i',  // payload: h'6869'
  };
  uint8_t buffer[16];
  msgs::DataFrame frame;
  frame.encoding_id = 1;
  frame.payload = {'h', 'i'};
  const int64_t bytes_out =
      msgs::EncodeDataFrame(frame, buffer, sizeof(buffer));
  ASSERT_EQ(static_cast<int64_t>(sizeof(kFrame)), bytes_out);
  EXPECT_EQ(0, memcmp(kFrame, buffer, sizeof(kFrame)));

  msgs::DataFrame decoded;
  ASSERT_EQ(static_cast<int64_t>(sizeof(kFrame)),
            msgs::DecodeDataFrame(kFrame, sizeof(kFrame), decoded));
  EXPECT_EQ(frame, decoded);
}

TEST(Lp2pMessagesTest, AgentCapabilities) {
  EXPECT_EQ(1100u, static_cast<uint64_t>(msgs::AgentCapability::kDataChannels));
  EXPECT_EQ(1200u,
            static_cast<uint64_t>(msgs::AgentCapability::kQuickTransport));
  EXPECT_EQ(1101u, static_cast<uint64_t>(msgs::Type::kDataChannelOpenRequest));
  EXPECT_EQ(1102u, static_cast<uint64_t>(msgs::Type::kDataChannelOpenResponse));
}

}  // namespace openscreen::osp

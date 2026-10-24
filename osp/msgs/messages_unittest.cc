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

}  // namespace openscreen::osp

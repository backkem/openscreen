// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/public/instance_request_ids.h"

#include "gtest/gtest.h"

namespace openscreen::osp {

// These tests validate RequestId generation for two instances with numbers 3
// and 7.

TEST(InstanceRequestIdsTest, StrictlyIncreasingRequestIdSequence) {
  InstanceRequestIds request_ids;

  EXPECT_EQ(1u, request_ids.GetNextRequestId(7));
  EXPECT_EQ(2u, request_ids.GetNextRequestId(7));
  EXPECT_EQ(3u, request_ids.GetNextRequestId(7));
  EXPECT_EQ(1u, request_ids.GetNextRequestId(3));
  EXPECT_EQ(4u, request_ids.GetNextRequestId(7));
  EXPECT_EQ(2u, request_ids.GetNextRequestId(3));
}

TEST(InstanceRequestIdsTest, ResetRequestId) {
  InstanceRequestIds request_ids;

  EXPECT_EQ(1u, request_ids.GetNextRequestId(7));
  EXPECT_EQ(2u, request_ids.GetNextRequestId(7));
  request_ids.ResetRequestId(7);
  EXPECT_EQ(1u, request_ids.GetNextRequestId(7));
  EXPECT_EQ(2u, request_ids.GetNextRequestId(7));
  EXPECT_EQ(1u, request_ids.GetNextRequestId(3));
  EXPECT_EQ(2u, request_ids.GetNextRequestId(3));
  request_ids.ResetRequestId(7);
  EXPECT_EQ(1u, request_ids.GetNextRequestId(7));
  EXPECT_EQ(3u, request_ids.GetNextRequestId(3));
}

TEST(InstanceRequestIdsTest, ResetAll) {
  InstanceRequestIds request_ids;

  EXPECT_EQ(1u, request_ids.GetNextRequestId(7));
  EXPECT_EQ(2u, request_ids.GetNextRequestId(7));
  EXPECT_EQ(1u, request_ids.GetNextRequestId(3));
  request_ids.Reset();
  EXPECT_EQ(1u, request_ids.GetNextRequestId(7));
  EXPECT_EQ(1u, request_ids.GetNextRequestId(3));
}

}  // namespace openscreen::osp

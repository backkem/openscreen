// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "osp/public/instance_request_ids.h"

namespace openscreen::osp {

InstanceRequestIds::InstanceRequestIds() = default;
InstanceRequestIds::~InstanceRequestIds() = default;

uint64_t InstanceRequestIds::GetNextRequestId(uint64_t instance_id) {
  // application.bs: "request-id and watch-id values are unsigned integer IDs
  // that are assigned from a counter kept by each agent that starts at 1 and
  // increments by 1 for each ID." Request IDs need not be unique across
  // agents: each agent matches responses only against its own requests.
  return ++request_ids_by_instance_id_[instance_id];
}

void InstanceRequestIds::ResetRequestId(uint64_t instance_id) {
  request_ids_by_instance_id_.erase(instance_id);
}

void InstanceRequestIds::Reset() {
  request_ids_by_instance_id_.clear();
}

}  // namespace openscreen::osp

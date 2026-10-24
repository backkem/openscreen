// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OSP_PUBLIC_INSTANCE_REQUEST_IDS_H_
#define OSP_PUBLIC_INSTANCE_REQUEST_IDS_H_

#include <cstdint>
#include <map>

namespace openscreen::osp {

// Tracks the next available message request ID per instance by its instance
// id. These can only be incremented while an instance is connected but can
// be reset on disconnection. All APIs that send CBOR requests to an instance
// share this counter, which starts at 1 and increments by 1 (application.bs
// "Requests, Responses, and Watches").
class InstanceRequestIds final {
 public:
  // Whether the agent is the QUIC client (listening agent) or server
  // (advertising agent).
  enum class Role {
    kClient,
    kServer,
  };

  InstanceRequestIds();
  InstanceRequestIds(const InstanceRequestIds&) = delete;
  InstanceRequestIds& operator=(const InstanceRequestIds&) = delete;
  InstanceRequestIds(InstanceRequestIds&&) noexcept = delete;
  InstanceRequestIds& operator=(InstanceRequestIds&&) noexcept = delete;
  ~InstanceRequestIds();

  uint64_t GetNextRequestId(uint64_t instance_id);
  void ResetRequestId(uint64_t instance_id);
  void Reset();

 private:
  std::map<uint64_t, uint64_t> request_ids_by_instance_id_;
};

}  // namespace openscreen::osp

#endif  // OSP_PUBLIC_INSTANCE_REQUEST_IDS_H_

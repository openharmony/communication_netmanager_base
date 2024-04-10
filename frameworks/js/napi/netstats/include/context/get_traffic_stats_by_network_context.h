/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMMUNICATION_NETMANAGER_BASE_GET_TRAFFIC_STATS_BY_NETWORK_CONTEXT_H
#define COMMUNICATION_NETMANAGER_BASE_GET_TRAFFIC_STATS_BY_NETWORK_CONTEXT_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include <napi/native_api.h>

#include "base_context.h"
#include "net_stats_info.h"

namespace OHOS {
namespace NetManagerStandard {
class GetTrafficStatsByNetworkContext final : public BaseContext {
public:
    GetTrafficStatsByNetworkContext() = delete;
    explicit GetTrafficStatsByNetworkContext(napi_env env, EventManager *manager);

    void SetType(uint32_t typ);
    void SetStart(uint32_t startTime);
    void SetEnd(uint32_t endTime);
    void SetSimId(uint32_t simId);
    uint32_t GetType() const;
    uint32_t GetStart() const;
    uint32_t GetEnd() const;
    uint32_t GetSimId() const;

    std::vector<NetStatsInfo> &GetNetStatsInfo();

    void ParseParams(napi_value *params, size_t paramsCount);

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);

    bool CheckNetworkParams(napi_value *params, size_t paramsCount);

private:
    uint32_t type_ = 0;
    uint32_t start_ = 0;
    uint32_t end_ = 0;
    uint32_t simId_;

    std::vector<NetStatsInfo> stats_;
};
} // namespace NetManagerStandard
} // namespace OHOS

#endif // COMMUNICATION_NETMANAGER_BASE_GET_TRAFFIC_STATS_BY_NETWORK_CONTEXT_H
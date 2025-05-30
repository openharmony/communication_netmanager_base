/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef NET_STATS_HISTORY_H
#define NET_STATS_HISTORY_H

#include <climits>
#include <vector>

#include "net_stats_info.h"
#include "net_stats_data_handler.h"

namespace OHOS {
namespace NetManagerStandard {
class NetStatsHistory {
public:
    NetStatsHistory() = default;
    ~NetStatsHistory() = default;
    int32_t GetHistory(std::vector<NetStatsInfo> &recv, uint64_t start = 0, uint64_t end = LONG_MAX);
    int32_t GetHistory(std::vector<NetStatsInfo> &recv, uint32_t uid, uint64_t start = 0, uint64_t end = LONG_MAX);
    int32_t GetHistory(std::vector<NetStatsInfo> &recv, const std::string &iface, uint64_t start = 0,
                       uint64_t end = LONG_MAX);
    int32_t GetHistory(std::vector<NetStatsInfo> &recv, const std::string &iface, uint32_t uid, uint64_t start = 0,
                       uint64_t end = LONG_MAX);
    int32_t GetHistoryByIdent(std::vector<NetStatsInfo> &recv, const std::string &ident, uint64_t start = 0,
                              uint64_t end = LONG_MAX);
    int32_t GetHistory(std::vector<NetStatsInfo> &recv, uint32_t uid, const std::string &ident, uint64_t start = 0,
                              uint64_t end = LONG_MAX);
    int32_t GetHistoryByIdentAndUserId(std::vector<NetStatsInfo> &recv, const std::string &ident, int32_t userId,
                    uint64_t start = 0, uint64_t end = LONG_MAX);
};

} // namespace NetManagerStandard
} // namespace OHOS

#endif // NET_STATS_HISTORY_H
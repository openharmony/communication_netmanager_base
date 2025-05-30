/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "net_stats_callback.h"

#include "netsys_controller.h"
#include "net_stats_constants.h"
#include "net_mgr_log_wrapper.h"
#include "net_stats_constants.h"

namespace OHOS {
namespace NetManagerStandard {
void NetStatsCallback::RegisterNetStatsCallback(const sptr<INetStatsCallback> &callback)
{
    if (callback == nullptr) {
        NETMGR_LOG_E("The parameter callback is null");
        return;
    }
    std::lock_guard<ffrt::mutex> lock(statsCallbackMetux_);
    uint32_t callBackNum = netStatsCallback_.size();
    NETMGR_LOG_D("netStatsCallback_ callback num [%{public}d]", callBackNum);
    if (callBackNum >= LIMIT_STATS_CALLBACK_NUM) {
        NETMGR_LOG_E("netStatsCallback_ callback num cannot more than [%{public}d]", LIMIT_STATS_CALLBACK_NUM);
        return;
    }

    for (uint32_t i = 0; i < callBackNum; i++) {
        if (callback->AsObject().GetRefPtr() == netStatsCallback_[i]->AsObject().GetRefPtr()) {
            NETMGR_LOG_I("netStatsCallback_ had this callback");
            return;
        }
    }
    NETMGR_LOG_I("netStatsCallback_ add callback.");
    netStatsCallback_.emplace_back(callback);
}

void NetStatsCallback::UnregisterNetStatsCallback(const sptr<INetStatsCallback> &callback)
{
    if (callback == nullptr) {
        NETMGR_LOG_E("callback is null");
        return;
    }
    std::lock_guard<ffrt::mutex> lock(statsCallbackMetux_);
    for (auto iter = netStatsCallback_.begin(); iter != netStatsCallback_.end(); ++iter) {
        if (callback->AsObject().GetRefPtr() == (*iter)->AsObject().GetRefPtr()) {
            netStatsCallback_.erase(iter);
            NETMGR_LOG_I("netStatsCallback_ erase callback.");
            return;
        }
    }
}

int32_t NetStatsCallback::NotifyNetIfaceStatsChanged(const std::string &iface)
{
    NETMGR_LOG_D("NotifyNetIfaceStatsChanged info: iface[%{public}s]", iface.c_str());
    std::lock_guard<ffrt::mutex> lock(statsCallbackMetux_);
    auto iter = std::remove_if(netStatsCallback_.begin(), netStatsCallback_.end(), [&iface](const auto &item) {
        return item == nullptr || item->NetIfaceStatsChanged(iface) == NETMANAGER_ERR_IPC_CONNECT_STUB_FAIL;
    });
    netStatsCallback_.erase(iter, netStatsCallback_.end());
    return NETMANAGER_SUCCESS;
}

int32_t NetStatsCallback::NotifyNetUidStatsChanged(const std::string &iface, uint32_t uid)
{
    NETMGR_LOG_D("UpdateIfacesStats info: iface[%{public}s] uid[%{public}d]", iface.c_str(), uid);
    std::lock_guard<ffrt::mutex> lock(statsCallbackMetux_);
    auto iter = std::remove_if(netStatsCallback_.begin(), netStatsCallback_.end(), [&iface, uid](const auto &item) {
        return item == nullptr || item->NetUidStatsChanged(iface, uid) == NETMANAGER_ERR_IPC_CONNECT_STUB_FAIL;
    });
    netStatsCallback_.erase(iter, netStatsCallback_.end());
    return NETMANAGER_SUCCESS;
}
} // namespace NetManagerStandard
} // namespace OHOS

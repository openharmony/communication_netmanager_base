/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef NETLINK_MANAGER_H
#define NETLINK_MANAGER_H

#include <memory>
#include <mutex>
#include <vector>

#include "i_notify_callback.h"

#define NET_SYMBOL_VISIBLE __attribute__ ((visibility("default")))
namespace OHOS {
namespace nmd {
class NET_SYMBOL_VISIBLE NetlinkManager {
public:
    static constexpr uint32_t NFLOG_QUOTA_GROUP = 1;
    static constexpr uint32_t NETFILTER_STRICT_GROUP = 2;
    static constexpr uint32_t NFLOG_WAKEUP_GROUP = 3;
    static constexpr uint32_t UEVENT_GROUP = 0xffffffff;

    NetlinkManager();
    ~NetlinkManager();

    int32_t StartListener();
    int32_t StopListener();
    int32_t RegisterNetlinkCallback(sptr<NetsysNative::INotifyCallback> callback);
    int32_t UnregisterNetlinkCallback(sptr<NetsysNative::INotifyCallback> callback);

private:
    std::shared_ptr<std::vector<sptr<NetsysNative::INotifyCallback>>> callbacks_;
    std::mutex linkCallbackMutex_;
};
} // namespace nmd
} // namespace OHOS
#endif // NETLINK_MANAGER_H
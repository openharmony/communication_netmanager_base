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

#ifndef NET_POLICY_EVENT_HANDLER_H
#define NET_POLICY_EVENT_HANDLER_H

#include <iostream>

#include "event_handler.h"
#include "event_runner.h"
#include "ffrt.h"
#include "net_policy_core.h"
#include "singleton.h"

namespace OHOS {
namespace NetManagerStandard {
class NetPolicyCore;
class NetPolicyEventHandler {
public:
    static constexpr int32_t MSG_DEVICE_IDLE_LIST_UPDATED = 1;
    static constexpr int32_t MSG_DEVICE_IDLE_MODE_CHANGED = 2;
    static constexpr int32_t MSG_POWER_SAVE_MODE_CHANGED = 3;
    static constexpr int32_t MSG_UID_REMOVED = 4;
    static constexpr int32_t MSG_POWER_SAVE_LIST_UPDATED = 5;
    static constexpr int32_t MSG_UID_STATE_FOREGROUND = 6;
    static constexpr int32_t MSG_UID_STATE_BACKGROUND = 7;

    NetPolicyEventHandler(const std::shared_ptr<NetPolicyCore> &core, ffrt::queue& ffrtQueue);
    ~NetPolicyEventHandler() = default;

    /**
     * Process the event from EventHandler
     *
     * @param eventId The event id
     * @param policyEvent The informations passed from other core
     */
    void ProcessEvent(int32_t eventId, std::shared_ptr<PolicyEvent> eventData);

    void SendEvent(const AppExecFwk::InnerEvent::Pointer &event, int64_t delayTime);

private:
    std::shared_ptr<NetPolicyCore> core_;
    ffrt::queue& ffrtQueue_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NET_POLICY_EVENT_HANDLER_H
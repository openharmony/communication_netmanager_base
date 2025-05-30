/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef NETMANAGER_BASE_RAIIXCOLLIETIMER_H
#define NETMANAGER_BASE_RAIIXCOLLIETIMER_H
 
#include "net_mgr_log_wrapper.h"
#include "xcollie/xcollie.h"
 
namespace OHOS::NetManagerStandard {
class RaiiXCollieTimer {
    DISALLOW_COPY_AND_MOVE(RaiiXCollieTimer);
 
public:
    RaiiXCollieTimer(const std::string &name, unsigned int timeout)
    {
        timerId = OHOS::HiviewDFX::XCollie::GetInstance().SetTimer(name, timeout, nullptr, nullptr,
                                                                   OHOS::HiviewDFX::XCOLLIE_FLAG_LOG);
    }
    ~RaiiXCollieTimer()
    {
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    }
 
private:
    int timerId = -1;
};
} // namespace OHOS::NetManagerStandard
 
#endif //NETMANAGER_BASE_RAIIXCOLLIETIMER_H
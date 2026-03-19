/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "policy_ani.h"
#include "errorcode_convertor.h"
#include "net_manager_constants.h"
#include "net_mgr_log_wrapper.h"
#include "wrapper.rs.h"

namespace OHOS {
namespace NetManagerAni {

rust::String GetErrorCodeAndMessage(int32_t &errorCode)
{
    NetManagerStandard::NetBaseErrorCodeConvertor convertor;
    return rust::string(convertor.ConvertErrorCode(errorCode));
}

NetAccessPolicyInner GetSelfNetworkAccessPolicy(int32_t &ret)
{
    NetAccessPolicyInner policy = {true, true};
    NetManagerStandard::NetAccessPolicy netPolicy;
    ret = NetManagerStandard::NetPolicyClient::GetInstance().GetSelfNetworkAccessPolicy(netPolicy);
    if (ret == NetManagerStandard::NETMANAGER_SUCCESS) {
        policy.allowWiFi = netPolicy.allowWiFi;
        policy.allowCellular = netPolicy.allowCellular;
    }
    return policy;
}

} // namespace NetManagerAni
} // namespace OHOS

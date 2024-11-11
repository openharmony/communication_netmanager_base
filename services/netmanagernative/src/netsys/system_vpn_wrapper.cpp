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

#include "system_vpn_wrapper.h"

#include <unistd.h>
#include "netnative_log_wrapper.h"
#include "netmanager_base_common_utils.h"
#include "net_manager_constants.h"

namespace OHOS {
namespace nmd {
using namespace NetManagerStandard;

SystemVpnWrapper::SystemVpnWrapper()
{
    isIpSecAccess_ = access(IPSEC_CMD_PATH, F_OK) == 0;
    vpnFfrtQueue_ = std::make_shared<ffrt::queue>("SystemVpnWrapper");
}

SystemVpnWrapper::~SystemVpnWrapper()
{
    vpnFfrtQueue_.reset();
}

void SystemVpnWrapper::ExecuteUpdate(SysVpnStageCode stage)
{
    NETNATIVE_LOGI("run ExecuteUpdate stage %{public}d", stage);
    std::string param = std::string(IPSEC_CMD_PATH) + " ";
    switch (stage) {
        case SysVpnStageCode::VPN_STAGE_RESTART:
            param.append(VPN_STAGE_RESTART);
            break;
        case SysVpnStageCode::VPN_STAGE_UP_HOME:
            param.append(VPN_STAGE_UP_HOME);
            break;
        case SysVpnStageCode::VPN_STAGE_SWANCTL_LOAD:
            param.append(VPN_STAGE_SWANCTL_LOAD).append(SWAN_CTL_FILE);
            break;
        case SysVpnStageCode::VPN_STAGE_L2TP_LOAD:
            param.append(VPN_STAGE_L2TP_LOAD).append(L2TP_CFG).append(IPSEC_L2TP_CTL);
            break;
        case SysVpnStageCode::VPN_STAGE_L2TP_CTL:
            param.append(VPN_STAGE_L2TP_CTL);
            break;
        case SysVpnStageCode::VPN_STAGE_DOWN_HOME:
            param.append(VPN_STAGE_DOWN_HOME);
            break;
        case SysVpnStageCode::VPN_STAGE_STOP:
            param.append(VPN_STAGE_STOP);
            break;
        case SysVpnStageCode::VPN_STAGE_OPENVPN_RESTART:
            param.append(VPN_STAGE_OPENVPN_RESTART).append(OPENVPN_CONFIG_FILE);
            break;
        case SysVpnStageCode::VPN_STAGE_OPENVPN_STOP:
            param.append(VPN_STAGE_OPENVPN_STOP);
            break;
        default:
            NETNATIVE_LOGE("run ExecuteUpdate failed, unknown stage %{public}d", stage);
            return;
    }
    if (CommonUtils::ForkExec(param) == NETMANAGER_ERROR) {
        NETNATIVE_LOGE("run ExecuteUpdate failed");
    }
}

int32_t SystemVpnWrapper::Update(NetsysNative::SysVpnStageCode stage)
{
    if (!vpnFfrtQueue_) {
        NETNATIVE_LOGE("FFRT Init Fail");
        return NETMANAGER_ERROR;
    }

    if (!isIpSecAccess_) {
        NETNATIVE_LOGE("Update failed! exec program is not exist");
        return NETMANAGER_ERROR;
    }
#if UNITTEST_FORBID_FFRT // Forbid FFRT for unittest, which will cause crash in destructor process
    ExecuteUpdate(stage);
#else
    std::function<void()> update = std::bind(&SystemVpnWrapper::ExecuteUpdate, shared_from_this(), stage);
    vpnFfrtQueue_->submit(update);
#endif // UNITTEST_FORBID_FFRT
    return NetManagerStandard::NETMANAGER_SUCCESS;
}
} // namespace nmd
} // namespace OHOS
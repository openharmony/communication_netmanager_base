/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "net_mgr_log_wrapper.h"
#include "netmanager_base_permission.h"

namespace OHOS {
namespace NetManagerStandard {
bool NetManagerPermission::CheckPermissionWithCache(const std::string &permissionName)
{
    NETMGR_LOG_D("Net conn client fuzzer permissionName: %{public}s", permissionName.c_str());
    return true;
}

bool NetManagerPermission::CheckPermission(const std::string &permissionName)
{
    NETMGR_LOG_D("Net conn client fuzzer permissionName: %{public}s", permissionName.c_str());
    return true;
}

bool NetManagerPermission::IsSystemCaller()
{
    NETMGR_LOG_D("Is conn caller.");
    return true;
}
} // namespace NetManagerStandard
} // namespace OHOS
/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "net_manager_constants.h"
#include "route_manager.h"

#include "netsys_network.h"

namespace OHOS {
namespace nmd {
using namespace NetManagerStandard;

NetsysNetwork::NetsysNetwork(uint16_t netId) : netId_(netId) {}

int32_t NetsysNetwork::ClearInterfaces()
{
    std::lock_guard locker(mutex_);
    interfaces_.clear();
    return NETMANAGER_SUCCESS;
}

bool NetsysNetwork::ExistInterface(std::string &interfaceName)
{
    std::lock_guard locker(mutex_);
    return interfaces_.find(interfaceName) != interfaces_.end();
}
} // namespace nmd
} // namespace OHOS

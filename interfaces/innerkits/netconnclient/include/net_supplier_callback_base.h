/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NET_SUPPLIER_CALLBACK_BASE_H
#define NET_SUPPLIER_CALLBACK_BASE_H

#include <string>
#include <set>

#include "refbase.h"

#include "net_all_capabilities.h"
#include "net_manager_constants.h"

namespace OHOS {
namespace NetManagerStandard {
struct NetRequestBySpecifier {
    std::set<NetBearType> bearTypes = {};
    uint32_t registerType = REGISTER;
    NetRequestBySpecifier(const uint32_t &registerType, const std::set<NetBearType> &netBearTypes)
        : bearTypes(netBearTypes), registerType(registerType)
    {}
    NetRequestBySpecifier() = default;
}
class NetSupplierCallbackBase : public virtual RefBase {
public:
    virtual ~NetSupplierCallbackBase() = default;

    virtual int32_t RequestNetwork(const std::string &ident,
                                   const std::set<NetCap> &netCaps,
                                   const NetRequestBySpecifier &netRequestBySpecifier = {});
    virtual int32_t ReleaseNetwork(const std::string &ident, const std::set<NetCap> &netCaps);
};
} // NetManagerStandard
} // OHOS
#endif // NET_SUPPLIER_CALLBACK_BASE_H
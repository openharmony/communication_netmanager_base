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

#ifndef NET_SUPPLIER_CALLBACK_PROXY_H
#define NET_SUPPLIER_CALLBACK_PROXY_H

#include "iremote_proxy.h"

#include "i_net_supplier_callback.h"

namespace OHOS {
namespace NetManagerStandard {
class NetSupplierCallbackProxy : public IRemoteProxy<INetSupplierCallback> {
public:
    explicit NetSupplierCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~NetSupplierCallbackProxy();

public:
    int32_t RequestNetwork(const std::string &ident, const std::set<NetCap> &netCaps,
                           const NetRequest &netrequest = {}) override;
    int32_t ReleaseNetwork(const std::string &ident, const std::set<NetCap> &netCaps) override;
    int32_t AddRequest(const NetRequest &netrequest) override;
    int32_t RemoveRequest(const NetRequest &netrequest) override;

private:
    bool WriteInterfaceToken(MessageParcel &data);

private:
    static inline BrokerDelegator<NetSupplierCallbackProxy> delegator_;
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NET_CONN_CALLBACK_PROXY_H

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
#include "netfirewall_callback_proxy.h"
#include "netnative_log_wrapper.h"
#include "netsys_ipc_interface_code.h"

namespace OHOS {
namespace NetsysNative {
NetFirewallCallbackProxy::NetFirewallCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<INetFirewallCallback>(impl)
{}

int32_t NetFirewallCallbackProxy::OnIntercept(sptr<NetManagerStandard::InterceptRecord> &record)
{
    NETNATIVE_LOGI("Proxy OnIntercept");
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetFirewallCallbackProxy::GetDescriptor())) {
        NETNATIVE_LOGE("WriteInterfaceToken failed");
        return ERR_NULL_OBJECT;
    }
    if (!record->Marshalling(data)) {
        return ERR_NONE;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        NETNATIVE_LOGE("Remote is null");
        return ERR_NULL_OBJECT;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(NetFirewallfaceCode::ON_INTERCEPT), data, reply, option);
    if (ret != ERR_NONE) {
        NETNATIVE_LOGE("Proxy SendRequest failed, ret code:[%{public}d]", ret);
    }
    return ret;
}
} // namespace NetsysNative
} // namespace OHOS
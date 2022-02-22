/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef NETMANAGER_BASE_NET_CONN_CALLBACK_OBSERVER_H
#define NETMANAGER_BASE_NET_CONN_CALLBACK_OBSERVER_H

#include "net_all_capabilities.h"
#include "net_conn_callback_stub.h"
#include "netmanager_base_event_manager.h"
#include "netmanager_base_napi_utils.h"

namespace OHOS::NetManagerStandard {
class NetConnCallbackObserver : public NetConnCallbackStub {
public:
    int32_t NetAvailable(sptr<NetHandle> &netHandle);

    int32_t NetCapabilitiesChange(sptr<NetHandle> &netHandle, const sptr<NetAllCapabilities> &netAllCap);

    int32_t NetConnectionPropertiesChange(sptr<NetHandle> &netHandle, const sptr<NetLinkInfo> &info);

    int32_t NetLost(sptr<NetHandle> &netHandle);

    int32_t NetUnavailable();

    int32_t NetBlockStatusChange(sptr<NetHandle> &netHandle, bool blocked);

private:
    static napi_value CreateNetHandle(napi_env env, NetHandle *handle);

    static napi_value CreateNetCapabilities(napi_env env, NetAllCapabilities *capabilities);

    static napi_value CreateConnectionProperties(napi_env env, NetLinkInfo *linkInfo);

    static napi_value CreateNetAvailableParam(napi_env env, void *data);

    static napi_value CreateNetCapabilitiesChangeParam(napi_env env, void *data);

    static napi_value CreateNetConnectionPropertiesChangeParam(napi_env env, void *data);

    static napi_value CreateNetLostParam(napi_env env, void *data);

    static napi_value CreateNetUnavailableParam(napi_env env, void *data);

    static napi_value CreateNetBlockStatusChangeParam(napi_env env, void *data);

    static void NetAvailableCallback(uv_work_t *work, int status);

    static void NetCapabilitiesChangeCallback(uv_work_t *work, int status);

    static void NetConnectionPropertiesChangeCallback(uv_work_t *work, int status);

    static void NetLostCallback(uv_work_t *work, int status);

    static void NetUnavailableCallback(uv_work_t *work, int status);

    static void NetBlockStatusChangeCallback(uv_work_t *work, int status);
};
} // namespace OHOS::NetManagerStandard

#endif /* NETMANAGER_BASE_NET_CONN_CALLBACK_OBSERVER_H */

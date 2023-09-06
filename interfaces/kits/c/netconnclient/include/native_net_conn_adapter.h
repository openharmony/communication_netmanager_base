/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef NATIVE_NET_CONN_ADAPTER_H
#define NATIVE_NET_CONN_ADAPTER_H

#include "http_proxy.h"
#include "native_net_conn_type.h"
#include "net_all_capabilities.h"
#include "net_handle.h"
#include "net_link_info.h"
#include "refbase.h"

namespace OHOS::NetManagerStandard {

int32_t Conv2NetHandle(NetHandle &netHandleObj, OH_NetConn_NetHandle *netHandle);

int32_t Conv2NetHandleObj(OH_NetConn_NetHandle *netHandle, NetHandle &netHandleObj);

int32_t Conv2NetHandleList(std::list<sptr<NetHandle>> &netHandleObjList, OH_NetConn_NetHandleList *netHandleList);

int32_t Conv2NetLinkInfo(NetLinkInfo &infoObj, OH_NetConn_NetLinkInfo *info);

int32_t Conv2NetAllCapabilities(NetAllCapabilities &netAllCapsObj, OH_NetConn_NetAllCapabilities *netAllCaps);

int32_t Conv2HttpProxy(HttpProxy &httpProxyObj, OH_NetConn_HttpProxy *httpProxy);

} // namespace OHOS::NetManagerStandard
#endif /* NATIVE_NET_CONN_ADAPTER_H */
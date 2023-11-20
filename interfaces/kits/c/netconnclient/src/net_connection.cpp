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

#include "net_connection.h"
#include "net_conn_client.h"
#include "net_connection_type.h"
#include "net_connection_adapter.h"
#include "net_manager_constants.h"
#include "net_mgr_log_wrapper.h"

using namespace OHOS::NetManagerStandard;

int32_t OH_NetConn_GetAddrInfo(char *host, char *serv, struct addrinfo *hint, struct addrinfo **res, int32_t netId)
{
    int32_t ret = NETMANAGER_SUCCESS;
    int status = 0;
    struct queryparam qp_param;
    if (host == nullptr || res == nullptr) {
        NETMGR_LOG_E("OH_NetConn_GetAddrInfo received invalid parameters");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }

    memset(&qp_param, 0, sizeof(struct queryparam));
    qp_param.qp_netid = netId;
    qp_param.qp_type = 0;

    status = getaddrinfo_ext(host, serv, hint, res, &qp_param);
    if (status < 0) {
        ret = NETMANAGER_ERR_PARAMETER_ERROR;
    }

    return ret;
}


int32_t OH_NetConn_FreeDnsResult(struct addrinfo *res)
{
    if (res == nullptr) {
        NETMGR_LOG_E("OH_NetConn_FreeDnsResult received invalid parameters");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }

    freeaddrinfo(res);

    return NETMANAGER_SUCCESS;
}

int32_t OH_NetConn_GetAllNets(OH_NetConn_NetHandleList *netHandleList)
{
    if (netHandleList == nullptr) {
        NETMGR_LOG_E("OH_NetConn_GetAllNets received invalid parameters");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }

    std::list<OHOS::sptr<NetHandle>> netHandleObjList;
    int32_t ret = NetConnClient::GetInstance().GetAllNets(netHandleObjList);
    int32_t retConv = Conv2NetHandleList(netHandleObjList, netHandleList);
    if (retConv != NETMANAGER_SUCCESS) {
        return retConv;
    }
    return ret;
}

int32_t OHOS_NetConn_RegisterDnsResolver(OH_NetConn_CustomDnsResolver resolver)
{
    if (resolver == nullptr) {
        NETMGR_LOG_E("OHOS_NetConn_RegisterDnsResolver received invalid parameters");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }

    int32_t ret = setdnsresolvehook(resolver);
    if (ret < 0) {
        ret = NETMANAGER_ERR_PARAMETER_ERROR;
    }
    return ret;
}

int32_t OHOS_NetConn_UnregisterDnsResolver()
{
    int32_t ret = removednsresolvehook();
    return ret;
}
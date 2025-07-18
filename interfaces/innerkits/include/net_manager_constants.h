/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef NETMANAGER_CONSTANTS_H
#define NETMANAGER_CONSTANTS_H

#include <stdint.h>

namespace OHOS {
namespace NetManagerStandard {
constexpr int NETMANAGER_ERROR = -1;
constexpr int NETSYS_SUCCESS = 0;
constexpr const char* CREATE_TABLE_IF_NOT_EXISTS = "CREATE TABLE IF NOT EXISTS ";
constexpr int32_t DEFAULT_GATEWAY_MASK_MAX_LENGTH = 24;

enum {
    NETMANAGER_COMMON = 0x00,
    NETMANAGER_DNS_RESOLVER_MANAGER = 0x01,
    NETMANAGER_NET_CONN_MANAGER = 0x03,
    NETMANAGER_NET_POLICY_MANAGER = 0x04,
};

enum {
    NETMANAGER_ERR_PERMISSION_DENIED = 201,
    NETMANAGER_ERR_NOT_SYSTEM_CALL = 202,
    NETMANAGER_ERR_PARAMETER_ERROR = 401,
    NETMANAGER_ERR_CAPABILITY_NOT_SUPPORTED = 801,
    NETMANAGER_SUCCESS = 0,
    NETMANAGER_ERR_INVALID_PARAMETER = 2100001,
    NETMANAGER_ERR_OPERATION_FAILED = 2100002,
    NETMANAGER_ERR_INTERNAL = 2100003,
    NETMANAGER_ERR_MEMCPY_FAIL = 2100101,
    NETMANAGER_ERR_MEMSET_FAIL = 2100102,
    NETMANAGER_ERR_STRCPY_FAIL = 2100103,
    NETMANAGER_ERR_STRING_EMPTY = 2100104,
    NETMANAGER_ERR_LOCAL_PTR_NULL = 2100105,
    NETMANAGER_ERR_DESCRIPTOR_MISMATCH = 2100201,
    NETMANAGER_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL = 2100202,
    NETMANAGER_ERR_WRITE_DATA_FAIL = 2100203,
    NETMANAGER_ERR_WRITE_REPLY_FAIL = 2100204,
    NETMANAGER_ERR_READ_DATA_FAIL = 2100205,
    NETMANAGER_ERR_READ_REPLY_FAIL = 2100206,
    NETMANAGER_ERR_IPC_CONNECT_STUB_FAIL = 2100207,
    NETMANAGER_ERR_GET_PROXY_FAIL = 2100208,
    NETMANAGER_ERR_STATUS_EXIST = 2100209,
};

enum {
    NETMANAGER_EXT_ERR_PERMISSION_DENIED = 201,
    NETMANAGER_EXT_ERR_NOT_SYSTEM_CALL = 202,
    NETMANAGER_EXT_ERR_PARAMETER_ERROR = 401,
    NETMANAGER_EXT_ERR_CAPABILITY_NOT_SUPPORTED = 801,
    NETMANAGER_EXT_SUCCESS = 0,
    NETMANAGER_EXT_ERR_INVALID_PARAMETER = 2200001,
    NETMANAGER_EXT_ERR_OPERATION_FAILED = 2200002,
    NETMANAGER_EXT_ERR_INTERNAL = 2200003,
    NETMANAGER_EXT_ERR_MEMCPY_FAIL = 2200101,
    NETMANAGER_EXT_ERR_MEMSET_FAIL = 2200102,
    NETMANAGER_EXT_ERR_STRCPY_FAIL = 2200103,
    NETMANAGER_EXT_ERR_STRING_EMPTY = 2200104,
    NETMANAGER_EXT_ERR_LOCAL_PTR_NULL = 2200105,
    NETMANAGER_EXT_ERR_DESCRIPTOR_MISMATCH = 2200201,
    NETMANAGER_EXT_ERR_WRITE_DESCRIPTOR_TOKEN_FAIL = 2200202,
    NETMANAGER_EXT_ERR_WRITE_DATA_FAIL = 2200203,
    NETMANAGER_EXT_ERR_WRITE_REPLY_FAIL = 2200204,
    NETMANAGER_EXT_ERR_READ_DATA_FAIL = 2200205,
    NETMANAGER_EXT_ERR_READ_REPLY_FAIL = 2200206,
    NETMANAGER_EXT_ERR_IPC_CONNECT_STUB_FAIL = 2200207,
    NETMANAGER_EXT_ERR_GET_PROXY_FAIL = 2200208,
};

enum {
    ETHERNET_ERR_INIT_FAIL = 2201001,
    ETHERNET_ERR_EMPTY_CONFIGURATION = 2201002,
    ETHERNET_ERR_DUMP = 2201003,
    ETHERNET_ERR_DEVICE_CONFIGURATION_INVALID = 2201004,
    ETHERNET_ERR_DEVICE_INFORMATION_NOT_EXIST = 2201005,
    ETHERNET_ERR_DEVICE_NOT_LINK = 2201006,
    ETHERNET_ERR_USER_CONIFGURATION_WRITE_FAIL = 2201007,
    ETHERNET_ERR_USER_CONIFGURATION_CLEAR_FAIL = 2201008,
    ETHERNET_ERR_CONVERT_CONFIGURATINO_FAIL = 2201009
};

enum {
    NETWORKSHARE_ERROR_UNKNOWN_TYPE = 2202002,
    NETWORKSHARE_ERROR_UNKNOWN_IFACE = 2202003,
    NETWORKSHARE_ERROR_UNAVAIL_IFACE = 2202004,
    NETWORKSHARE_ERROR_WIFI_SHARING = 2202005,
    NETWORKSHARE_ERROR_BT_SHARING = 2202006,
    NETWORKSHARE_ERROR_USB_SHARING = 2202007,
    NETWORKSHARE_ERROR_SHARING_IFACE_ERROR = 2202008,
    NETWORKSHARE_ERROR_ENABLE_FORWARDING_ERROR = 2202009,
    NETWORKSHARE_ERROR_INTERNAL_ERROR = 2202010,
    NETWORKSHARE_ERROR_IFACE_CFG_ERROR = 2202011,
    NETWORKSHARE_ERROR_DHCPSERVER_ERROR = 2202012,
    NETWORKSHARE_ERROR_ISSHARING_CALLBACK_ERROR = 2202013,
};

enum {
    NETWORKVPN_ERROR_REFUSE_CREATE_VPN = 2203001,
    NETWORKVPN_ERROR_VPN_EXIST = 2203002,
    NETWORKVPN_ERROR_INVALID_FD = 2203004,
};

enum {
    NET_MDNS_ERR_UNKNOWN = 2204001,
    NET_MDNS_ERR_CALLBACK_NOT_FOUND = 2204002,
    NET_MDNS_ERR_CALLBACK_DUPLICATED = 2204003,
    NET_MDNS_ERR_PAYLOAD_PARSER_FAIL = 2204004,
    NET_MDNS_ERR_EMPTY_PAYLOAD = 2204005,
    NET_MDNS_ERR_TIMEOUT = 2204006,
    NET_MDNS_ERR_ILLEGAL_ARGUMENT = NETMANAGER_ERR_PARAMETER_ERROR,
    NET_MDNS_ERR_SERVICE_INSTANCE_DUPLICATE = 2204007,
    NET_MDNS_ERR_SERVICE_INSTANCE_NOT_FOUND = 2204008,
    NET_MDNS_ERR_SEND = 2204009,
    NET_MDNS_ERR_WRITE_DUMP = 2204010,
};

#ifdef FEATURE_WEARABLE_DISTRIBUTED_NET_ENABLE
enum {
    NETMANAGER_WEARABLE_DISTRIBUTED_NET_ERR_START_FAIL = 2205001,
    NETMANAGER_WEARABLE_DISTRIBUTED_NET_ERR_STOP_FAIL = 2205002,
    NETMANAGER_WEARABLE_DISTRIBUTED_NET_ERR_INIT_FAIL = 2205003,
    NETMANAGER_WEARABLE_DISTRIBUTED_NET_ERR_INVALID_PORT_ID = 2205004,
    NETMANAGER_WEARABLE_DISTRIBUTED_NET_ERR_INVALID_UDP_PORT_ID = 2205005,
    NETMANAGER_WEARABLE_DISTRIBUTED_NET_ERR_INVALID_TCP_PORT_ID = 2205006,
    NETMANAGER_WEARABLE_DISTRIBUTED_NET_ERR_INVALID_RULE_TYPE = 2205007,
    NETMANAGER_WEARABLE_DISTRIBUTED_NET_ERR_INVALID_SUPPLIER_ID = 2205008,
    NETMANAGER_WEARABLE_DISTRIBUTED_NET_ERR_IPTABLES_COMMAND_INVALID = 2205009,
};
#endif

enum {
    NETWORKVPN_ERROR_VNIC_EXIST = 2206001,
};

#ifdef FEATURE_NET_FIREWALL_ENABLE
enum {
    FIREWALL_SUCCESS = 0,
    FIREWALL_ERR_PERMISSION_DENIED = 201,
    FIREWALL_ERR_PARAMETER_ERROR = 401,
    FIREWALL_ERR_INVALID_PARAMETER = 2100001,
    FIREWALL_ERR_OPERATION_FAILED = 2100002,
    FIREWALL_ERR_INTERNAL = 2100003,
    FIREWALL_ERR_NO_USER = 29400000,
    FIREWALL_ERR_EXCEED_MAX_RULE = 29400001,
    FIREWALL_ERR_EXCEED_MAX_IP = 29400002,
    FIREWALL_ERR_EXCEED_MAX_PORT = 29400003,
    FIREWALL_ERR_EXCEED_MAX_DOMAIN = 29400004,
    FIREWALL_ERR_EXCEED_ALL_MAX_DOMAIN = 29400005,
    FIREWALL_ERR_NO_RULE = 29400006,
    FIREWALL_ERR_DNS_RULE_DUPLICATION = 29400007,
};
#endif

enum class NetSlotTech {
    SLOT_TYPE_GSM = 1,
    SLOT_TYPE_LTE = 9,
    SLOT_TYPE_LTE_CA = 10,
};

enum RegisterType {
    UNKOWN,
    REGISTER,
    REQUEST
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NETMANAGER_CONSTANTS_H

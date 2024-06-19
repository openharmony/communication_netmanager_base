/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef NETSYS_IPC_INTERFACE_CODE_H
#define NETSYS_IPC_INTERFACE_CODE_H

/* SAID: 1158 */
namespace OHOS {
namespace NetsysNative {
enum class NetsysInterfaceCode {
    NETSYS_SET_RESOLVER_CONFIG_PARCEL,
    NETSYS_SET_RESOLVER_CONFIG,
    NETSYS_GET_RESOLVER_CONFIG,
    NETSYS_CREATE_NETWORK_CACHE,
    NETSYS_FLUSH_NETWORK_CACHE,
    NETSYS_DESTROY_NETWORK_CACHE,
    NETSYS_GET_ADDR_INFO,
    NETSYS_INTERFACE_SET_MTU,
    NETSYS_INTERFACE_GET_MTU,
    NETSYS_SET_TCP_BUFFER_SIZES,
    NETSYS_REGISTER_NOTIFY_CALLBACK,
    NETSYS_UNREGISTER_NOTIFY_CALLBACK,
    NETSYS_NETWORK_ADD_ROUTE,
    NETSYS_NETWORK_REMOVE_ROUTE,
    NETSYS_NETWORK_ADD_ROUTE_PARCEL,
    NETSYS_NETWORK_REMOVE_ROUTE_PARCEL,
    NETSYS_NETWORK_SET_DEFAULT,
    NETSYS_NETWORK_GET_DEFAULT,
    NETSYS_NETWORK_CLEAR_DEFAULT,
    NETSYS_GET_PROC_SYS_NET,
    NETSYS_SET_PROC_SYS_NET,
    NETSYS_NETWORK_CREATE_PHYSICAL,
    NETSYS_INTERFACE_ADD_ADDRESS,
    NETSYS_INTERFACE_DEL_ADDRESS,
    NETSYS_INTERFACE_SET_IP_ADDRESS,
    NETSYS_INTERFACE_SET_IFF_UP,
    NETSYS_NETWORK_ADD_INTERFACE,
    NETSYS_NETWORK_REMOVE_INTERFACE,
    NETSYS_NETWORK_DESTROY,
    NETSYS_GET_FWMARK_FOR_NETWORK,
    NETSYS_INTERFACE_SET_CONFIG,
    NETSYS_INTERFACE_GET_CONFIG,
    NETSYS_INTERFACE_GET_LIST,
    NETSYS_START_DHCP_CLIENT,
    NETSYS_STOP_DHCP_CLIENT,
    NETSYS_START_DHCP_SERVICE,
    NETSYS_STOP_DHCP_SERVICE,
    NETSYS_IPENABLE_FORWARDING,
    NETSYS_IPDISABLE_FORWARDING,
    NETSYS_ENABLE_NAT,
    NETSYS_DISABLE_NAT,
    NETSYS_IPFWD_ADD_INTERFACE_FORWARD,
    NETSYS_IPFWD_REMOVE_INTERFACE_FORWARD,
    NETSYS_BANDWIDTH_ENABLE_DATA_SAVER,
    NETSYS_BANDWIDTH_SET_IFACE_QUOTA,
    NETSYS_BANDWIDTH_REMOVE_IFACE_QUOTA,
    NETSYS_BANDWIDTH_ADD_DENIED_LIST,
    NETSYS_BANDWIDTH_REMOVE_DENIED_LIST,
    NETSYS_BANDWIDTH_ADD_ALLOWED_LIST,
    NETSYS_BANDWIDTH_REMOVE_ALLOWED_LIST,
    NETSYS_FIREWALL_SET_UID_ALLOWED_LIST_CHAIN,
    NETSYS_FIREWALL_SET_UID_DENIED_LIST_CHAIN,
    NETSYS_FIREWALL_ENABLE_CHAIN,
    NETSYS_FIREWALL_SET_UID_RULE,
    NETSYS_TETHER_DNS_SET,
    NETSYS_START_DNS_PROXY_LISTEN,
    NETSYS_STOP_DNS_PROXY_LISTEN,
    NETSYS_GET_SHARING_NETWORK_TRAFFIC,
    NETSYS_GET_TOTAL_STATS,
    NETSYS_GET_UID_STATS,
    NETSYS_GET_IFACE_STATS,
    NETSYS_GET_ALL_STATS_INFO,
    NETSYS_DISALLOW_INTERNET,
    NETSYS_SET_IPTABLES_CMD_FOR_RES,
    NETSYS_SET_INTERNET_PERMISSION,
    NETSYS_NETWORK_CREATE_VIRTUAL,
    NETSYS_NETWORK_ADD_UIDS,
    NETSYS_NETWORK_DEL_UIDS,
    NETSYS_NETDIAG_PING_HOST,
    NETSYS_NETDIAG_GET_ROUTE_TABLE,
    NETSYS_NETDIAG_GET_SOCKETS_INFO,
    NETSYS_NETDIAG_GET_IFACE_CONFIG,
    NETSYS_NETDIAG_UPDATE_IFACE_CONFIG,
    NETSYS_NETDIAG_SET_IFACE_ACTIVE_STATE,
    NETSYS_ADD_STATIC_ARP,
    NETSYS_DEL_STATIC_ARP,
    NETSYS_REGISTER_DNS_RESULT_LISTENER,
    NETSYS_UNREGISTER_DNS_RESULT_LISTENER,
    NETSYS_REGISTER_DNS_HEALTH_LISTENER,
    NETSYS_UNREGISTER_DNS_HEALTH_LISTENER,
    NETSYS_GET_COOKIE_STATS,
    NETSYS_GET_NETWORK_SHARING_TYPE,
    NETSYS_UPDATE_NETWORK_SHARING_TYPE,
#ifdef FEATURE_NET_FIREWALL_ENABLE
    NETSYS_NET_FIREWALL_SET_DEFAULT_ACTION,
    NETSYS_NET_FIREWALL_ADD_IP_RULES,
    NETSYS_NET_FIREWALL_UPDATE_IP_RULE,
    NETSYS_NET_FIREWALL_DELETE_IP_RULES,
    NETSYS_NET_FIREWALL_SET_DNS_RULES,
    NETSYS_NET_FIREWALL_SET_DOMAIN_RULES,
    NETSYS_NET_FIREWALL_CLEAR_RULES,
    NETSYS_NET_FIREWALL_REGISTER,
    NETSYS_NET_FIREWALL_UNREGISTER,
#endif
    NETSYS_NETWORK_SET_IPV6_PRIVCAY_EXTENSION,
    NETSYS_NETWORK_ENABLE_IPV6,
    NETSYS_GET_ALL_CONTAINER_STATS_INFO,
    NETSYS_SET_NETWORK_ACCESS_POLICY,
    NETSYS_DEL_NETWORK_ACCESS_POLICY,
    NETSYS_NOTIFY_NETWORK_BEARER_TYPE_CHANGE,
    NETSYS_NETWORK_START_CLAT,
    NETSYS_NETWORK_STOP_CLAT,
    NETSYS_SET_IP_AN_UID_RULE,
    NETSYS_CLEAR_IP_AN_UID_RULE,
    NETSYS_CLEAR_FIREWALL_RULE,
};

enum class NotifyInterfaceCode {
    ON_INTERFACE_ADDRESS_UPDATED = 0,
    ON_INTERFACE_ADDRESS_REMOVED,
    ON_INTERFACE_ADDED,
    ON_INTERFACE_REMOVED,
    ON_INTERFACE_CHANGED,
    ON_INTERFACE_LINK_STATE_CHANGED,
    ON_ROUTE_CHANGED,
    ON_DHCP_SUCCESS,
    ON_BANDWIDTH_REACHED_LIMIT,
};

enum class NetDiagInterfaceCode {
    ON_NOTIFY_PING_RESULT = 0,
};

enum class NetDnsResultInterfaceCode {
    ON_DNS_RESULT_REPORT = 0,
};

enum class NetDnsHealthInterfaceCode {
    ON_DNS_HEALTH_REPORT = 0,
};

#ifdef FEATURE_NET_FIREWALL_ENABLE
enum class NetFirewallfaceCode {
    ON_INTERCEPT = 0,
};
#endif

} // namespace NetsysNative
} // namespace OHOS
#endif // NETSYS_IPC_INTERFACE_CODE_H

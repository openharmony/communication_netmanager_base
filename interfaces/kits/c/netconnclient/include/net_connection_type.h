/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef NATIVE_NET_CONN_TYPE_H
#define NATIVE_NET_CONN_TYPE_H

/**
 * @addtogroup NetConnection
 * @{
 *
 * @brief Provides the data structures for the C APIs of the network connection module for network management.
 *
 * @since 11
 * @version 1.0
 */

/**
 * @file net_connection_type.h
 * @brief Defines the data structures for the C APIs of the network connection module.
 *
 * @library libnet_connection.so
 * @syscap SystemCapability.Communication.NetManager.Core
 * @since 11
 * @version 1.0
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NETCONN_MAX_NET_SIZE 32
#define NETCONN_MAX_BEARER_TYPE_SIZE 32
#define NETCONN_MAX_CAP_SIZE 32
#define NETCONN_MAX_ADDR_SIZE 32
#define NETCONN_MAX_ROUTE_SIZE 64
#define NETCONN_MAX_EXCLUSION_SIZE 256
#define NETCONN_MAX_STR_LEN 256
#define NETCONN_MAX_JUMP_NUM 30

/**
 * @brief Defines network capabilities.
 *
 * @since 11
 * @version 1.0
 */
typedef enum NetConn_NetCap {
    /** MMS */
    NETCONN_NET_CAPABILITY_MMS = 0,
    /** SUPL */
    NETCONN_NET_CAPABILITY_SUPL = 1,
    /** DUN */
    NETCONN_NET_CAPABILITY_DUN = 2,
    /** IA */
    NETCONN_NET_CAPABILITY_IA = 3,
    /** XCAP */
    NETCONN_NET_CAPABILITY_XCAP = 4,
    /** Not Metered */
    NETCONN_NET_CAPABILITY_NOT_METERED = 11,
    /** Internet */
    NETCONN_NET_CAPABILITY_INTERNET = 12,
    /** Not VPN */
    NETCONN_NET_CAPABILITY_NOT_VPN = 15,
    /** Validated */
    NETCONN_NET_CAPABILITY_VALIDATED = 16,
    /** portal */
    NETCONN_NET_CAPABILITY_PORTAL = 17,
    /** Checking connectivity */
    NETCONN_NET_CAPABILITY_CHECKING_CONNECTIVITY = 31
} NetConn_NetCap;

/**
 * @brief Defines network bearer types.
 *
 * @since 11
 * @version 1.0
 */
typedef enum NetConn_NetBearerType {
    /** Cellular network */
    NETCONN_BEARER_CELLULAR = 0,
    /** WIFI */
    NETCONN_BEARER_WIFI = 1,
    /** Bluetooth */
    NETCONN_BEARER_BLUETOOTH = 2,
    /** Ethernet */
    NETCONN_BEARER_ETHERNET = 3,
    /** VPN */
    NETCONN_BEARER_VPN = 4,
} NetConn_NetBearerType;

/**
 * @brief Defines the network handle.
 *
 * @since 11
 * @version 1.0
 */
typedef struct NetConn_NetHandle {
    /** Network ID */
    int32_t netId;
} NetConn_NetHandle;

/**
 * @brief Defines network capabilities.
 *
 * @since 11
 * @version 1.0
 */
typedef struct NetConn_NetCapabilities {
    /** Uplink bandwidth */
    uint32_t linkUpBandwidthKbps;
    /** Downlink bandwidth */
    uint32_t linkDownBandwidthKbps;
    /** Network capability list */
    NetConn_NetCap netCaps[NETCONN_MAX_CAP_SIZE];
    /** Actual size of the network capability list */
    int32_t netCapsSize;
    /** Bearer type list */
    NetConn_NetBearerType bearerTypes[NETCONN_MAX_BEARER_TYPE_SIZE];
    /** Actual size of the bearer type list */
    int32_t bearerTypesSize;
} NetConn_NetCapabilities;

/**
 * @brief Defines the network address.
 *
 * @since 11
 * @version 1.0
 */
typedef struct NetConn_NetAddr {
    /** Network address family */
    uint8_t family;
    /** Prefix length */
    uint8_t prefixlen;
    /** Port number */
    uint8_t port;
    /** Address */
    char address[NETCONN_MAX_STR_LEN];
} NetConn_NetAddr;

/**
 * @brief Defines the route configuration information.
 *
 * @since 11
 * @version 1.0
 */
typedef struct NetConn_Route {
    /** Network interface */
    char iface[NETCONN_MAX_STR_LEN];
    /** Destination address */
    NetConn_NetAddr destination;
    /** Gateway address */
    NetConn_NetAddr gateway;
    /** Gateway exists or not */
    int32_t hasGateway;
    /** Default route or not */
    int32_t isDefaultRoute;
} NetConn_Route;

/**
 * @brief Defines the proxy configuration information.
 *
 * @since 11
 * @version 1.0
 */
typedef struct NetConn_HttpProxy {
    /** Host name */
    char host[NETCONN_MAX_STR_LEN];
    /** Exclusion list of proxy servers */
    char exclusionList[NETCONN_MAX_EXCLUSION_SIZE][NETCONN_MAX_STR_LEN];
    /** Actual size of the exclusion list */
    int32_t exclusionListSize;
    /** Port number */
    uint16_t port;
} NetConn_HttpProxy;

/**
 * @brief Defines the network connection properties.
 *
 * @since 11
 * @version 1.0
 */
typedef struct NetConn_ConnectionProperties {
    /** Network interface name */
    char ifaceName[NETCONN_MAX_STR_LEN];
    /** Domain name of the network connection */
    char domain[NETCONN_MAX_STR_LEN];
    /** TCP buffer size */
    char tcpBufferSizes[NETCONN_MAX_STR_LEN];
    /** MTU */
    uint16_t mtu;
    /** Address list */
    NetConn_NetAddr netAddrList[NETCONN_MAX_ADDR_SIZE];
    /** Actual size of the address list */
    int32_t netAddrListSize;
    /** DNS list */
    NetConn_NetAddr dnsList[NETCONN_MAX_ADDR_SIZE];
    /** Actual size of the DNS list */
    int32_t dnsListSize;
    /** Route list */
    NetConn_Route routeList[NETCONN_MAX_ROUTE_SIZE];
    /** Actual size of the route list */
    int32_t routeListSize;
    /** HTTP proxy information */
    NetConn_HttpProxy httpProxy;
} NetConn_ConnectionProperties;

/**
 * @brief Defines the network handle list.
 *
 * @since 11
 * @version 1.0
 */
typedef struct NetConn_NetHandleList {
    /** Network handle list */
    NetConn_NetHandle netHandles[NETCONN_MAX_NET_SIZE];
    /** Actual size of the network handle list */
    int32_t netHandleListSize;
} NetConn_NetHandleList;

/**
 * @brief Pointer to the custom DNS resolver.
 *
 * @param host The host name to query.
 * @param serv Service name.
 * @param hint Pointer to the addrinfo structure.
 * @param res Store DNS query results and return them in a linked list format.
 *
 * @since 11
 * @version 1.0
 */
typedef int (*OH_NetConn_CustomDnsResolver)(const char *host, const char *serv, const struct addrinfo *hint,
                                            struct addrinfo **res);

typedef void (*OH_NetConn_AppHttpProxyChange)(NetConn_HttpProxy *proxy);

typedef struct NetConn_NetSpecifier {
    NetConn_NetCapabilities caps;
    char *bearerPrivateIdentifier;
} NetConn_NetSpecifier;

typedef void (*OH_NetConn_NetworkAvailable)(NetConn_NetHandle *netHandle);

typedef void (*OH_NetConn_NetCapabilitiesChange)(NetConn_NetHandle *netHandle,
                                                 NetConn_NetCapabilities *netCapabilities);

typedef void (*OH_NetConn_NetConnectionPropertiesChange)(NetConn_NetHandle *netHandle,
                                                         NetConn_ConnectionProperties *connConnetionProperties);

typedef void (*OH_NetConn_NetLost)(NetConn_NetHandle *netHandle);

typedef void (*OH_NetConn_NetUnavailable)(void);

typedef void (*OH_NetConn_NetBlockStatusChange)(NetConn_NetHandle *netHandle, bool blocked);

typedef struct NetConn_NetConnCallback {
    OH_NetConn_NetworkAvailable onNetworkAvailable;
    OH_NetConn_NetCapabilitiesChange onNetCapabilitiesChange;
    OH_NetConn_NetConnectionPropertiesChange onConnetionProperties;
    OH_NetConn_NetLost onNetLost;
    OH_NetConn_NetUnavailable onNetUnavailable;
    OH_NetConn_NetBlockStatusChange onNetBlockStatusChange;
} NetConn_NetConnCallback;

constexpr int32_t NETCONN_MAX_RTT_NUM = 4;
typedef struct NetConn_ProbeResultInfo {
    uint8_t lossRate;

    uint32_t rtt[NETCONN_MAX_RTT_NUM];
} NetConn_ProbeResultInfo;

typedef enum NetConn_PacketsType {
    /** ICMP */
    NETCONN_PACKETS_ICMP = 0,
    /** UDP */
    NETCONN_PACKETS_UDP = 1,
} NetConn_PacketsType;

typedef struct NetConn_TraceRouteOption {
    /** Maximum number of jumps */
    uint8_t maxJumpNumber; /** default NETCONN_MAX_JUMP_NUM */
    /** Packets Type */
    NetConn_PacketsType packetsType; /** default ICMP */
} NetConn_TraceRouteOption;

typedef struct NetConn_TraceRouteInfo {
    /** Number of jumps */
    uint8_t jumpNo;
    /** host name or address */
    char address[NETCONN_MAX_STR_LEN];
    /** RTT in millisecond */
    uint32_t rtt[NETCONN_MAX_RTT_NUM];
} NetConn_TraceRouteInfo;

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* NATIVE_NET_CONN_TYPE_H */

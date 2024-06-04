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
#ifndef NET_FIREWALL_MATCH_H
#define NET_FIREWALL_MATCH_H

#include <bpf/bpf_helpers.h>

#include "netfirewall_utils.h"
#include "netfirewall_bitmap.h"
#include "netfirewall_map.h"
#include "netfirewall_event.h"
#include "netfirewall_def.h"

/**
 * @brief Get the appuid from skb
 *
 * @param skb struct __sk_buff
 * @return appid with type __u32
 */
static __always_inline __u32 get_appuid(struct __sk_buff *skb)
{
    return bpf_get_socket_uid(skb);
}

/**
 * @brief swap tuple ports at egress direction
 *
 * @param tuple struct match_tuple
 */
static __always_inline void swap_tuple_ports(struct match_tuple *tuple)
{
    __be16 tmp = tuple->sport;
    tuple->sport = tuple->dport;
    tuple->dport = tmp;
}

/**
 * @brief swap tuple addrs at egress direction
 *
 * @param tuple struct match_tuple
 */
static __always_inline void swap_tuple_addrs(struct match_tuple *tuple)
{
    if (tuple->family == AF_INET) {
        __be32 tmp = tuple->ipv4.saddr;
        tuple->ipv4.saddr = tuple->ipv4.daddr;
        tuple->ipv4.daddr = tmp;
    } else {
        struct in6_addr tmp = tuple->ipv6.saddr;
        tuple->ipv6.saddr = tuple->ipv6.daddr;
        tuple->ipv6.daddr = tmp;
    }
}

/**
 * @brief Get the match tuple from skb
 *
 * @param skb struct __sk_buff of packet
 * @param tuple struct match_tuple
 * @param dir enum stream_dir
 * @return true if success or false if an error occurred
 */
static __always_inline bool get_match_tuple(struct __sk_buff *skb, struct match_tuple *tuple, enum stream_dir dir)
{
    if (!skb || !tuple) {
        return false;
    }

    __u32 l3_nhoff = get_l3_nhoff(skb);
    __u32 l4_nhoff = get_l4_nhoff(skb);
    __u8 protocol = 0;
    if (skb->family == AF_INET) {
        load_l3_v4_addrs(skb, l3_nhoff, &(tuple->ipv4.saddr), &(tuple->ipv4.daddr));
    } else {
        load_l3_v6_addrs(skb, l3_nhoff, &(tuple->ipv6.saddr), &(tuple->ipv6.daddr));
    }
    if (!load_l4_protocol(skb, l3_nhoff, &protocol)) {
        return false;
    }
    tuple->dir = dir;
    tuple->family = skb->family;
    tuple->appuid = get_appuid(skb);
    tuple->protocol = protocol;

    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        load_l4_ports(skb, l4_nhoff, protocol, &(tuple->sport), &(tuple->dport));
        if (protocol == IPPROTO_TCP) {
            load_l4_header_flags(skb, l4_nhoff, &(tuple->rst));
        }
    }
    if (dir == EGRESS) {
        swap_tuple_addrs(tuple);
        swap_tuple_ports(tuple);
    }
    return true;
}

/**
 * @brief lookup key or other_key from bpf map
 *
 * @param map bpf map pointer
 * @param key key need to lookup
 * @param other_key when key not found, then lookup other_key
 * @return value with type struct bitmap of the key or other_key
 */
static __always_inline struct bitmap *lookup_map(void *map, void *key, void *other_key)
{
    struct bitmap *result = bpf_map_lookup_elem(map, key);
    if (!result) {
        result = bpf_map_lookup_elem(map, other_key);
    }
    return result;
}

/**
 * @brief lookup addr bitmap use the given tuple
 *
 * @param tuple struct match_tuple get from skb
 * @param key out param for lookup result
 * @return true if success or false if an error occurred
 */
static __always_inline bool match_addrs(struct match_tuple *tuple, action_key *key)
{
    if (!tuple || !key) {
        return false;
    }

    struct bitmap *result = NULL;
    bool ingress = tuple->dir == INGRESS;

    if (tuple->family == AF_INET) {
        struct ipv4_lpm_key other_lpm_key = {
            .prefixlen = 32,
            .data = OTHER_IP4_KEY,
        };
        struct ipv4_lpm_key lpm_key = {
            .prefixlen = 32,
            .data = tuple->ipv4.saddr,
        };

        result = lookup_map(GET_MAP(ingress, saddr), &lpm_key, &other_lpm_key);
        if (result) {
            log_dbg2(DBG_MATCH_SADDR, tuple->dir, (__u32)tuple->ipv4.saddr, result->val[0]);
            bitmap_and(key->val, result->val);
            result = NULL;
        }

        lpm_key.data = tuple->ipv4.daddr;
        result = lookup_map(GET_MAP(ingress, daddr), &lpm_key, &other_lpm_key);
        if (result) {
            log_dbg2(DBG_MATCH_DADDR, tuple->dir, (__u32)tuple->ipv4.daddr, result->val[0]);
            bitmap_and(key->val, result->val);
        }
    } else {
        struct ipv6_lpm_key other_lpm_key = {
            .prefixlen = 128,
        };
        struct ipv6_lpm_key lpm_key = {
            .prefixlen = 128,
        };
        memset(&(other_lpm_key.data), 0xff, sizeof(other_lpm_key.data));

        memcpy(&(lpm_key.data), &(tuple->ipv6.saddr), sizeof(lpm_key.data));
        result = lookup_map(GET_MAP(ingress, saddr6), &lpm_key, &other_lpm_key);
        if (result) {
            bitmap_and(key->val, result->val);
            result = NULL;
        }

        memcpy(&(lpm_key.data), &(tuple->ipv6.daddr), sizeof(lpm_key.data));
        result = lookup_map(GET_MAP(ingress, daddr6), &lpm_key, &other_lpm_key);
        if (result) {
            bitmap_and(key->val, result->val);
        }
    }
    return true;
}

/**
 * @brief lookup port bitmap use the given tuple
 *
 * @param tuple struct match_tuple get from skb
 * @param key out param for lookup result
 * @return true if success or false if an error occurred
 */
static __always_inline bool match_ports(struct match_tuple *tuple, action_key *key)
{
    if (!tuple || !key) {
        return false;
    }

    __u8 protocol = tuple->protocol;
    port_key other_port_key = OTHER_PORT_KEY;
    bool ingress = tuple->dir == INGRESS;
    struct bitmap *result = NULL;

    result = lookup_map(GET_MAP(ingress, sport), &(tuple->sport), &other_port_key);
    if (result) {
        log_dbg2(DBG_MATCH_SPORT, tuple->dir, (__u32)tuple->sport, result->val[0]);
        bitmap_and(key->val, result->val);
        result = NULL;
    }

    result = lookup_map(GET_MAP(ingress, dport), &(tuple->dport), &other_port_key);
    if (result) {
        log_dbg2(DBG_MATCH_DPORT, tuple->dir, (__u32)tuple->dport, result->val[0]);
        bitmap_and(key->val, result->val);
    }
    return true;
}

/**
 * @brief lookup protocol bitmap use the given tuple
 *
 * @param tuple struct match_tuple get from skb
 * @param key out param for lookup result
 * @return true if success or false if an error occurred
 */
static __always_inline bool match_protocol(struct match_tuple *tuple, action_key *key)
{
    if (!tuple || !key) {
        return false;
    }

    proto_key other_proto_key = OTHER_PROTO_KEY;
    bool ingress = tuple->dir == INGRESS;
    struct bitmap *result = NULL;

    result = lookup_map(GET_MAP(ingress, proto), &(tuple->protocol), &other_proto_key);
    if (result) {
        log_dbg2(DBG_MATCH_PROTO, tuple->dir, (__u32)tuple->protocol, result->val[0]);
        bitmap_and(key->val, result->val);
    }

    return true;
}

/**
 * @brief lookup appuid bitmap use the given tuple
 *
 * @param tuple struct match_tuple get from skb
 * @param key out param for lookup result
 * @return true if success or false if an error occurred
 */
static __always_inline bool match_appuid(struct match_tuple *tuple, action_key *key)
{
    if (!tuple || !key) {
        return false;
    }

    appuid_key other_appuid_key = OTHER_APPUID_KEY;
    bool ingress = tuple->dir == INGRESS;
    struct bitmap *result = NULL;

    result = lookup_map(GET_MAP(ingress, appuid), &(tuple->appuid), &other_appuid_key);
    if (result) {
        log_dbg2(DBG_MATCH_APPUID, tuple->dir, (__u32)tuple->appuid, result->val[0]);
        bitmap_and(key->val, result->val);
    }

    return true;
}

/**
 * @brief lookup action key bitmap use the given tuple
 *
 * @param tuple struct match_tuple get from skb
 * @param key out param for lookup result
 * @return true if success or false if an error occurred
 */
static __always_inline bool match_action_key(struct match_tuple *tuple, action_key *key)
{
    if (!tuple || !key) {
        return false;
    }

    memset(key, 0xff, sizeof(action_key));

    if (!match_addrs(tuple, key)) {
        return false;
    }

    if (!match_ports(tuple, key)) {
        return false;
    }

    if (!match_protocol(tuple, key)) {
        return false;
    }

    if (!match_appuid(tuple, key)) {
        return false;
    }

    log_dbg(DBG_ACTION_KEY, tuple->dir, key->val[0]);
    return true;
}

/**
 * @brief lookup action with action_key use the given tuple
 *
 * @param tuple struct match_tuple get from skb
 * @param key out param for lookup result
 * @return true if success or false if an error occurred
 */
static __always_inline enum sk_action match_action(struct match_tuple *tuple, action_key *key)
{
    if (!tuple || !key) {
        return SK_PASS;
    }

    enum sk_action sk_act = SK_PASS;
    bool ingress = tuple->dir == INGRESS;
    default_action_key default_key = ingress ? DEFAULT_ACT_IN_KEY : DEFAULT_ACT_OUT_KEY;
    action_val *default_action = bpf_map_lookup_elem(&DEFAULT_ACTION_MAP, &default_key);
    action_val *action = bpf_map_lookup_elem(GET_MAP(ingress, action), key);

    int set_bits = bitmap_count(key->val);
    if ((set_bits > 1 || !action) && default_action) {
        sk_act = *default_action;
    } else if (action) {
        sk_act = *action;
    }
    log_dbg(DBG_MATCH_ACTION, tuple->dir, sk_act);
    return sk_act;
}
#endif // NET_FIREWALL_MATCH_H

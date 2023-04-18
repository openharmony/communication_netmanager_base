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

#include <dlfcn.h>
#include <gtest/gtest.h>

#include "dns_config_client.h"
#include "dns_param_cache.h"
#include "dns_resolv_listen.h"
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace NetsysNative {
using namespace testing::ext;
using namespace OHOS::nmd;
constexpr const char *DNS_SO_PATH = "libnetsys_client.z.so";
struct resolv_config {
    int32_t error;
    int32_t timeout_ms;
    uint32_t retry_count;
    char nameservers[MAX_SERVER_NUM][MAX_SERVER_LENGTH + 1];
};
struct ParamWrapper {
    char *host;
    char *serv;
    struct addrinfo *hint;
};

typedef union {
    struct sockaddr sa;
    struct sockaddr_in6 sin6;
    struct sockaddr_in sin;
} AlignedSockAddr;

struct addr_info_wrapper {
    uint32_t ai_flags;
    uint32_t ai_family;
    uint32_t ai_sockType;
    uint32_t ai_protocol;
    uint32_t ai_addrLen;
    AlignedSockAddr ai_addr;
    char ai_canonName[MAX_CANON_NAME + 1];
};

typedef int32_t (*GetConfig)(uint16_t netId, struct resolv_config *config);
typedef int32_t (*GetCache)(uint16_t netId, struct ParamWrapper param, struct addr_info_wrapper addr_info[MAX_RESULTS],
                            uint32_t *num);

typedef int32_t (*SetCache)(uint16_t netId, struct ParamWrapper param, struct addrinfo *res);

class DnsResolvListenTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DnsResolvListenTest::SetUpTestCase() {}

void DnsResolvListenTest::TearDownTestCase() {}

void DnsResolvListenTest::SetUp() {}

void DnsResolvListenTest::TearDown() {}

HWTEST_F(DnsResolvListenTest, SetResolverConfigTest001, TestSize.Level1)
{
    NETNATIVE_LOGI("SetResolverConfigTest001 enter");
    DnsParamCache dnsParCache;
    std::vector<std::string> servers;
    std::vector<std::string> domains;
    servers.resize(MAX_SERVER_NUM + 1);
    uint16_t netId = 1;
    uint16_t baseTimeoutMsec = 0;
    uint8_t retryCount = 0;
    int32_t ret = dnsParCache.SetResolverConfig(netId, baseTimeoutMsec, retryCount, servers, domains);
    EXPECT_EQ(ret, -ENOENT);
}

HWTEST_F(DnsResolvListenTest, NetSysGetResolvConfTest001, TestSize.Level1)
{
    NETNATIVE_LOGI("NetSysGetResolvConf001 enter");
    void *handle = dlopen(DNS_SO_PATH, RTLD_LAZY);
    if (handle == NULL) {
        NETNATIVE_LOGI("StartListenTest002 dlopen err %{public}s", dlerror());
        return;
    }
    GetConfig func = (GetConfig)dlsym(handle, "NetSysGetResolvConf");
    if (func == NULL) {
        NETNATIVE_LOGI("dlsym err %{public}s\n", dlerror());
        return;
    }

    resolv_config config = {0};
    int ret = func(0, &config);
    dlclose(handle);
    EXPECT_EQ(ret, -ENOENT);
}

HWTEST_F(DnsResolvListenTest, NetSysGetResolvConfTest002, TestSize.Level1)
{
    NETNATIVE_LOGI("StartListen enter");
    DnsResolvListen dnsResolvListen;
    dnsResolvListen.StartListen();

    NETNATIVE_LOGI("NetSysGetResolvConf002 enter");
    void *handle = dlopen(DNS_SO_PATH, RTLD_LAZY);
    if (handle == NULL) {
        NETNATIVE_LOGI("StartListenTest002 dlopen err %{public}s", dlerror());
        return;
    }
    GetConfig func = (GetConfig)dlsym(handle, "NetSysGetResolvConf");
    if (func == NULL) {
        NETNATIVE_LOGI("dlsym err %{public}s\n", dlerror());
        return;
    }

    resolv_config config = {0};
    int ret = func(3, &config);
    dlclose(handle);
    EXPECT_EQ(ret, -ENOENT);
}

HWTEST_F(DnsResolvListenTest, ProcSetCacheCommandTest001, TestSize.Level1)
{
    NETNATIVE_LOGI("ProcSetCacheCommandTest001 enter");
    void *handle = dlopen(DNS_SO_PATH, RTLD_LAZY);
    if (handle == NULL) {
        NETNATIVE_LOGI("ProcSetCacheCommandTest001 dlopen err %{public}s", dlerror());
        return;
    }
    SetCache func = (SetCache)dlsym(handle, "NetSysSetResolvCache");
    if (func == NULL) {
        NETNATIVE_LOGI("ProcSetCacheCommandTest001 dlsym err %{public}s\n", dlerror());
        return;
    }
    std::string host = "www.1234.com";
    std::string serv;
    struct addrinfo *hint = nullptr;
    struct addrinfo *res = nullptr;
    struct ParamWrapper param = {const_cast<char *>(host.c_str()), const_cast<char *>(serv.c_str()),
                                 (struct addrinfo *)hint};
    int32_t ret = func(0, param, res);
    EXPECT_NE(ret, 0);
    dlclose(handle);
}

HWTEST_F(DnsResolvListenTest, ProcGetCacheCommandTest001, TestSize.Level1)
{
    NETNATIVE_LOGI("ProcGetCacheCommandTest001 enter");
    void *handle = dlopen(DNS_SO_PATH, RTLD_LAZY);
    if (handle == NULL) {
        NETNATIVE_LOGI("ProcGetCacheCommandTest001 dlopen err %{public}s", dlerror());
        return;
    }
    GetCache func = (GetCache)dlsym(handle, "NetSysGetResolvCache");
    if (func == NULL) {
        NETNATIVE_LOGI("ProcGetCacheCommandTest001 dlsym err %{public}s\n", dlerror());
        return;
    }
    std::string host = "www.1234.com";
    std::string serv;
    struct addrinfo *hint = nullptr;
    struct ParamWrapper param = {const_cast<char *>(host.c_str()), const_cast<char *>(serv.c_str()),
                                 (struct addrinfo *)hint};
    uint32_t num = 0;
    struct addr_info_wrapper addr_info[MAX_RESULTS] = {{0}};
    int32_t ret = func(0, param, addr_info, &num);
    EXPECT_EQ(ret, -ENOENT);
    dlclose(handle);
}
} // namespace NetsysNative
} // namespace OHOS

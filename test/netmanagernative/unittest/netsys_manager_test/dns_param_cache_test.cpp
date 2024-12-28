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

#include <gtest/gtest.h>

#ifdef GTEST_API_
#define private public
#define protected public
#endif

#include "dns_config_client.h"
#include "dns_param_cache.h"
#include "netnative_log_wrapper.h"

namespace OHOS {
namespace NetsysNative {
using namespace testing::ext;
using namespace OHOS::nmd;
class DNSParamCacheTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DNSParamCacheTest::SetUpTestCase() {}

void DNSParamCacheTest::TearDownTestCase() {}

void DNSParamCacheTest::SetUp() {}

void DNSParamCacheTest::TearDown() {}

HWTEST_F(DNSParamCacheTest, SetResolverConfigTest001, TestSize.Level1)
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

HWTEST_F(DNSParamCacheTest, SetResolverConfigTest002, TestSize.Level1)
{
    NETNATIVE_LOGI("SetResolverConfigTest002 enter");
    DnsParamCache dnsParCache;
    std::vector<std::string> servers;
    std::vector<std::string> domains;
    servers.resize(MAX_SERVER_NUM + 1);
    std::string hostName = "hoseName";
    AddrInfo addrInfo;
    for (size_t i = 0; i < MAX_SERVER_NUM; i++) {
        dnsParCache.CreateCacheForNet(i + 1);
        dnsParCache.SetDnsCache(i, hostName.append(std::to_string(i)), addrInfo);
        servers.emplace_back(hostName);
    }
    uint16_t netId = 1;
    uint16_t baseTimeoutMsec = 0;
    uint8_t retryCount = 0;
    int32_t ret = dnsParCache.SetResolverConfig(netId, baseTimeoutMsec, retryCount, servers, domains);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(DNSParamCacheTest, SetResolverConfigTest003, TestSize.Level1)
{
    NETNATIVE_LOGI("SetResolverConfigTest003 enter");
    DnsParamCache dnsParCache;
    std::vector<std::string> servers;
    std::vector<std::string> domains;
    servers.resize(MAX_SERVER_NUM + 1);
    uint16_t netId = 1;
    std::string hostName = "hoseName";
    dnsParCache.GetDnsCache(netId, hostName);
    AddrInfo addrInfo;
    addrInfo.aiFlags = 100;
    for (size_t i = 0; i < MAX_SERVER_NUM; i++) {
        dnsParCache.CreateCacheForNet(i);
        dnsParCache.SetDnsCache(i, hostName.append(std::to_string(i)), addrInfo);
        servers.emplace_back(hostName.append(std::to_string(i)));
    }
    
    uint16_t baseTimeoutMsec = 100;
    uint8_t retryCount = 2;
    int32_t ret = dnsParCache.SetResolverConfig(netId, baseTimeoutMsec, retryCount, servers, domains);
    EXPECT_EQ(ret, 0);
    netId = 100;
    ret = dnsParCache.GetResolverConfig(netId, servers, domains, baseTimeoutMsec, retryCount);
    EXPECT_EQ(ret, -ENOENT);
    netId = 1;
    ret = dnsParCache.GetResolverConfig(netId, servers, domains, baseTimeoutMsec, retryCount);
    EXPECT_EQ(ret, 0);
    std::string info;
    dnsParCache.GetDumpInfo(info);
}

HWTEST_F(DNSParamCacheTest, CreateCacheForNetTest, TestSize.Level1)
{
    NETNATIVE_LOGI("CreateCacheForNetTest enter");
    DnsParamCache dnsParCache;
    uint16_t netId = 1;
    dnsParCache.SetDefaultNetwork(netId);
    int32_t ret = dnsParCache.CreateCacheForNet(netId);
    EXPECT_EQ(ret, 0);
    ret = dnsParCache.CreateCacheForNet(netId);
    EXPECT_EQ(ret, -EEXIST);
    netId = 0;
    std::string hostName = "hostName";
    dnsParCache.SetCacheDelayed(netId, hostName);
    netId = 2;
    dnsParCache.SetCacheDelayed(netId, hostName);
}

HWTEST_F(DNSParamCacheTest, DestroyNetworkCacheTest, TestSize.Level1)
{
    NETNATIVE_LOGI("DestroyNetworkCacheTest enter");
    DnsParamCache dnsParCache;
    uint16_t netId = 1;
    int32_t ret = dnsParCache.DestroyNetworkCache(netId);
    EXPECT_EQ(ret, -ENOENT);
    dnsParCache.SetDefaultNetwork(netId);
    dnsParCache.CreateCacheForNet(netId);
    ret = dnsParCache.DestroyNetworkCache(netId);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(DNSParamCacheTest, EnableIpv6Test01, TestSize.Level1)
{
    DnsParamCache dnsParCache;
    uint16_t netId = 1;
    dnsParCache.EnableIpv6(netId);
    EXPECT_FALSE(dnsParCache.IsIpv6Enable(netId));
}

HWTEST_F(DNSParamCacheTest, IsIpv6EnableTest01, TestSize.Level1)
{
    DnsParamCache dnsParCache;
    uint16_t netId = 0;
    EXPECT_TRUE(netId == dnsParCache.defaultNetId_);

    bool ret = dnsParCache.IsIpv6Enable(netId);
    EXPECT_FALSE(ret);
}

HWTEST_F(DNSParamCacheTest, GetResolverConfigTest05, TestSize.Level1)
{
    DnsParamCache dnsParCache;
    std::vector<std::string> servers;
    std::vector<std::string> domains;
    servers.resize(MAX_SERVER_NUM + 1);
    uint16_t netId = 0;
    std::string hostName = "hoseName";
    dnsParCache.GetDnsCache(netId, hostName);
    AddrInfo addrInfo;
    addrInfo.aiFlags = 100;
    for (size_t i = 0; i < MAX_SERVER_NUM; i++) {
        dnsParCache.CreateCacheForNet(i);
        dnsParCache.SetDnsCache(i, hostName.append(std::to_string(i)), addrInfo);
        servers.emplace_back(hostName.append(std::to_string(i)));
    }

    uint16_t baseTimeoutMsec = 100;
    uint8_t retryCount = 2;
    int32_t ret = dnsParCache.GetResolverConfig(netId, servers, domains, baseTimeoutMsec, retryCount);
    EXPECT_TRUE(netId == dnsParCache.defaultNetId_);

    uint32_t uid = 1;
    ret = dnsParCache.GetResolverConfig(netId, uid, servers, domains, baseTimeoutMsec, retryCount);
    EXPECT_TRUE(netId == dnsParCache.defaultNetId_);
    ret = dnsParCache.GetResolverConfig(netId, uid, servers, domains, baseTimeoutMsec, retryCount);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(DNSParamCacheTest, GetDnsCacheTest01, TestSize.Level1)
{
    DnsParamCache dnsParCache;
    uint16_t netId = 0;
    std::string hostName = "";
    auto ret = dnsParCache.GetDnsCache(netId, hostName);
    EXPECT_TRUE(netId == dnsParCache.defaultNetId_);
}

HWTEST_F(DNSParamCacheTest, GetUserDefinedServerFlagTest001, TestSize.Level1)
{
    NETNATIVE_LOGI("GetUserDefinedServerFlagTest001 enter");
    DnsParamCache dnsParCache;
    std::vector<NetManagerStandard::UidRange> uidRanges;
    NetManagerStandard::UidRange uidrange1(10000, 20000);
    uidRanges.push_back(uidrange1);
    uint16_t netId = 0;
    bool flag = false;
    dnsParCache.SetDefaultNetwork(netId);
    dnsParCache.CreateCacheForNet(netId);
    int32_t ret = dnsParCache.GetUserDefinedServerFlag(netId, flag, 10001);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(DNSParamCacheTest, GetUserDefinedServerFlagTest002, TestSize.Level1)
{
    NETNATIVE_LOGI("GetUserDefinedServerFlagTest002 enter");
    DnsParamCache dnsParCache;
    uint16_t netId = 0;
    bool flag = false;
    dnsParCache.SetDefaultNetwork(netId);
    dnsParCache.CreateCacheForNet(netId);
    int32_t ret = dnsParCache.GetUserDefinedServerFlag(netId, flag);
    EXPECT_EQ(ret, 0);
}
} // namespace NetsysNative
} // namespace OHOS

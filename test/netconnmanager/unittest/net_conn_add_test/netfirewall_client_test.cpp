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

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <random>
#include <linux/if_tun.h>

#include "iservice_registry.h"
#include "netmanager_ext_test_security.h"
#include "netmgr_ext_log_wrapper.h"
#include "system_ability_definition.h"

#ifdef GTEST_API_
#define private public
#define protected public
#endif
#include "net_manager_constants.h"

#include "i_netfirewall_service.h"
#include "netfirewall_client.h"
#include "netfirewall_common.h"
#include "netfirewall_proxy.h"
#include "netfirewall_service.h"

namespace OHOS {
namespace NetManagerStandard {
namespace {
using namespace testing::ext;
int32_t g_rowId = 0;
constexpr int32_t MAX_TEST_CNT = 1;
constexpr int32_t MAX_USER_RULE = 1;
constexpr uint32_t APPID_TEST01 = 2034;
constexpr int32_t USER_ID1 = 100;
constexpr int32_t USER_ID2 = 101;
const uint16_t LOCAL_START_PORT = 10020;
const uint16_t LOCAL_END_PORT = 1003;
const uint16_t REMOTE_START_PORT = 1002;
const uint16_t REMOTE_END_PORT = 10030;
constexpr int32_t MAX_IPS = 1;
constexpr int32_t MAX_PORTS = 1;
constexpr int32_t MAX_DOMAINS = 1;
const int32_t MAX_RULE_DESCRITION_LEN = 256;

std::vector<NetFirewallIpParam> GetIpList(const std::string &addressStart, uint8_t type, uint8_t family = FAMILY_IPV6)
{
    const uint8_t mask = 24;
    const int32_t gap = 10;
    const int32_t hexWidth = 4;
    std::vector<NetFirewallIpParam> localParamList;
    NetFirewallIpParam localParam;
    localParam.family = family;
    localParam.type = type;
    std::string ip;
    std::stringstream ss;
    for (int32_t i = 0; i < MAX_IPS; i++) {
        ss.str("");
        ss.clear();
        ss << addressStart;
        if (family == FAMILY_IPV4) {
            ss << (i * gap);
            inet_pton(AF_INET, ss.str().c_str(), &localParam.ipv4.startIp);
        } else {
            ss << std::hex << std::setw(hexWidth) << std::setfill('0') << (i * gap);
            inet_pton(AF_INET6, ss.str().c_str(), &localParam.ipv6.startIp);
        }
        if (type == MULTIPLE_IP) {
            ss.str("");
            ss.clear();
            ss << addressStart;
            if (family == FAMILY_IPV4) {
                ss << (i * gap);
                inet_pton(AF_INET, ss.str().c_str(), &localParam.ipv4.endIp);
            } else {
                ss << std::hex << std::setw(hexWidth) << std::setfill('0') << (i * gap + gap);
                inet_pton(AF_INET6, ss.str().c_str(), &localParam.ipv6.endIp);
            }
        } else {
            localParam.mask = mask;
        }
        localParamList.emplace_back(std::move(localParam));
    }
    return localParamList;
}

std::vector<NetFirewallPortParam> GetPortList(const uint16_t startPort, const uint16_t endPort)
{
    const int32_t offset = 20;
    std::vector<NetFirewallPortParam> localPortParamList;
    NetFirewallPortParam localPortParam;
    localPortParam.startPort = startPort;
    localPortParam.endPort = endPort;
    for (int32_t i = 0; i < MAX_PORTS; i++) {
        localPortParamList.emplace_back(std::move(localPortParam));
        localPortParam.startPort += offset;
        localPortParam.endPort += offset;
    }
    return localPortParamList;
}

std::string generateRandomString(int32_t length)
{
    std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charset.size() - 1);
    for (int32_t i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }
    return result;
}

sptr<NetFirewallRule> GetNetFirewallRuleSptr(NetFirewallRuleType ruleType = NetFirewallRuleType::RULE_IP,
    NetFirewallRuleDirection ruleDirection = NetFirewallRuleDirection::RULE_OUT, uint8_t type = SINGLE_IP)
{
    sptr<NetFirewallRule> rule = (std::make_unique<NetFirewallRule>()).release();
    if (!rule) {
        return rule;
    }
    rule->ruleId = 1;
    rule->userId = USER_ID1;
    rule->ruleName = generateRandomString(MAX_RULE_NAME_LEN);
    rule->ruleDescription = generateRandomString(MAX_RULE_DESCRITION_LEN);
    rule->ruleDirection = ruleDirection;
    rule->ruleAction = FirewallRuleAction::RULE_ALLOW;
    rule->ruleType = ruleType;
    rule->isEnabled = true;
    rule->appUid = APPID_TEST01;
    if (ruleType == NetFirewallRuleType::RULE_IP) {
        if (ruleDirection == NetFirewallRuleDirection::RULE_OUT) {
            rule->localIps = GetIpList("AA22:BB11:1122:CDEF:1111:AA99:8888:", type);
        } else {
            rule->remoteIps = GetIpList("AA22:BB11:1122:CDEF:2222:AA99:8888:", type);
        }
        rule->localPorts = GetPortList(LOCAL_START_PORT, LOCAL_END_PORT);
        rule->remotePorts = GetPortList(REMOTE_START_PORT, REMOTE_END_PORT);
    } else if (ruleType == NetFirewallRuleType::RULE_DOMAIN) {
        std::vector<NetFirewallDomainParam> domainList;
        NetFirewallDomainParam domain;
        domain.isWildcard = false;
        const std::string tmp = "www.openharmony.cn";
        for (int32_t i = 0; i < MAX_DOMAINS; i++) {
            domain.domain = tmp + std::to_string(i);
            domainList.emplace_back(domain);
        }
        rule->domains = domainList;
    } else {
        rule->dns.primaryDns = "192.168.1.245";
        rule->dns.standbyDns = "192.168.1.1";
    }

    return rule;
}

sptr<NetFirewallRule> GetNetFirewallIpV4RuleSptr(
    NetFirewallRuleDirection ruleDirection = NetFirewallRuleDirection::RULE_OUT, uint8_t type = SINGLE_IP)
{
    sptr<NetFirewallRule> rule = (std::make_unique<NetFirewallRule>()).release();
    if (!rule) {
        return rule;
    }
    rule->ruleId = 1;
    rule->userId = USER_ID1;
    rule->ruleName = generateRandomString(MAX_RULE_NAME_LEN);
    rule->ruleDescription = generateRandomString(MAX_RULE_DESCRITION_LEN);
    rule->ruleDirection = ruleDirection;
    rule->ruleAction = FirewallRuleAction::RULE_ALLOW;
    rule->ruleType = NetFirewallRuleType::RULE_IP;
    rule->isEnabled = true;
    rule->appUid = APPID_TEST01;
    if (ruleDirection == NetFirewallRuleDirection::RULE_OUT) {
        rule->localIps = GetIpList("192.168.1.", type, FAMILY_IPV4);
    } else {
        rule->remoteIps = GetIpList("192.168.2.", type, FAMILY_IPV4);
    }
    rule->localPorts = GetPortList(LOCAL_START_PORT, LOCAL_START_PORT);
    rule->remotePorts = GetPortList(REMOTE_START_PORT, REMOTE_START_PORT);

    return rule;
}

uint64_t g_startTimeTest = 0;
uint64_t g_endTimeTest = 0;
} // namespace

class NetFirewallClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    NetFirewallClient &netfirewallClient_ = NetFirewallClient::GetInstance();
};

void NetFirewallClientTest::SetUpTestCase() {}

void NetFirewallClientTest::TearDownTestCase() {}

void NetFirewallClientTest::SetUp() {}

void NetFirewallClientTest::TearDown() {}

HWTEST_F(NetFirewallClientTest, SetNetFirewallPolicy, TestSize.Level1)
{
    NetManagerExtAccessToken token;
    int32_t userId = 100;
    int32_t ret = -1;
    sptr<NetFirewallPolicy> status = new (std::nothrow) NetFirewallPolicy();
    g_startTimeTest = GetCurrentMilliseconds();
    for (int32_t i = 0; i < MAX_TEST_CNT; i++) {
        status->isOpen = true;
        status->inAction = (FirewallRuleAction)(1);
        status->outAction = FirewallRuleAction::RULE_ALLOW;
        ret = netfirewallClient_.SetNetFirewallPolicy(userId, status);
        std::cout << "SetNetFirewallPolicy " << i + 1 << " ret " << ret << std::endl;
    }
    g_endTimeTest = GetCurrentMilliseconds();
    std::cout << "CALL_TEST SetNetFirewallPolicy user " << userId << " call " << MAX_TEST_CNT << ", use time : " <<
        g_endTimeTest - g_startTimeTest << " ms" << std::endl;
    EXPECT_EQ(ret, 0);
}

HWTEST_F(NetFirewallClientTest, GetNetFirewallPolicy, TestSize.Level1)
{
    NetManagerExtAccessToken token;
    int32_t userId = 100;
    int32_t ret = -1;
    sptr<NetFirewallPolicy> status = new (std::nothrow) NetFirewallPolicy();
    g_startTimeTest = GetCurrentMilliseconds();
    for (int32_t i = 0; i < MAX_TEST_CNT; i++) {
        ret = netfirewallClient_.GetNetFirewallPolicy(userId, status);
        std::cout << "GetNetFirewallPolicy " << i + 1 << " ret " << ret << std::endl;
    }
    g_endTimeTest = GetCurrentMilliseconds();
    std::cout << "CALL_TEST GetNetFirewallPolicy user " << userId << " call " << MAX_TEST_CNT << ", use time : " <<
        g_endTimeTest - g_startTimeTest << " ms" << std::endl;
    EXPECT_EQ(ret, 0);
}

HWTEST_F(NetFirewallClientTest, AddNetFirewallRule001, TestSize.Level1)
{
    NetManagerExtAccessToken token;
    int32_t ruleId = 0;
    int32_t ret = -1;
    sptr<NetFirewallRule> rule = GetNetFirewallRuleSptr();
    g_startTimeTest = GetCurrentMilliseconds();
    for (int32_t i = 0; i < MAX_USER_RULE; i++) {
        if (i >= FIREWALL_USER_MAX_RULE) {
            rule->userId = USER_ID2;
        }
        uint64_t stime = GetCurrentMilliseconds();
        ret = netfirewallClient_.AddNetFirewallRule(rule, ruleId);
        std::cout << "AddNetFirewallRule IP " << i + 1 << " ruleId " << ruleId << ", use time : " <<
            GetCurrentMilliseconds() - stime << " ms" << std::endl;
        if (ret != FIREWALL_SUCCESS) {
            EXPECT_EQ(ret, FIREWALL_SUCCESS);
            break;
        }
    }
    g_rowId = ruleId;
    g_endTimeTest = GetCurrentMilliseconds();
    std::cout << "CALL_TEST AddNetFirewallRule user " << rule->userId << " call " << MAX_USER_RULE << ", use time : " <<
        g_endTimeTest - g_startTimeTest << " ms" << std::endl;
    EXPECT_EQ(ret, FIREWALL_SUCCESS);
}

HWTEST_F(NetFirewallClientTest, AddNetFirewallRule002, TestSize.Level1)
{
    NetManagerExtAccessToken token;
    int32_t ruleId = 0;
    int32_t ret = -1;
    sptr<NetFirewallRule> rule = GetNetFirewallRuleSptr(NetFirewallRuleType::RULE_DOMAIN);
    g_startTimeTest = GetCurrentMilliseconds();
    for (int32_t i = 0; i < MAX_USER_RULE; i++) {
        uint64_t stime = GetCurrentMilliseconds();
        ret = netfirewallClient_.AddNetFirewallRule(rule, ruleId);
        std::cout << "AddNetFirewallRule DOMAIN " << i + 1 << " ruleId " << ruleId << ", use time : " <<
            GetCurrentMilliseconds() - stime << " ms" << std::endl;
    }
    g_rowId = ruleId;
    g_endTimeTest = GetCurrentMilliseconds();
    std::cout << "CALL_TEST DOMAIN AddNetFirewallRule user " << rule->userId << " call " << MAX_USER_RULE <<
        ", use time : " << g_endTimeTest - g_startTimeTest << " ms" << std::endl;
    EXPECT_EQ(ret, FIREWALL_SUCCESS);
}

HWTEST_F(NetFirewallClientTest, AddNetFirewallRule003, TestSize.Level1)
{
    NetManagerExtAccessToken token;
    int32_t ruleId = 0;
    int32_t ret = -1;
    sptr<NetFirewallRule> rule = GetNetFirewallRuleSptr(NetFirewallRuleType::RULE_DNS);
    g_startTimeTest = GetCurrentMilliseconds();
    for (int32_t i = 0; i < MAX_USER_RULE; i++) {
        uint64_t stime = GetCurrentMilliseconds();
        ret = netfirewallClient_.AddNetFirewallRule(rule, ruleId);
        std::cout << "AddNetFirewallRule DSN " << i + 1 << " ruleId " << ruleId << ", use time : " <<
            GetCurrentMilliseconds() - stime << " ms" << std::endl;
    }
    g_rowId = ruleId;
    g_endTimeTest = GetCurrentMilliseconds();
    std::cout << "CALL_TEST DNS AddNetFirewallRule user " << rule->userId << " call " << MAX_USER_RULE <<
        ", use time : " << g_endTimeTest - g_startTimeTest << " ms" << std::endl;
    EXPECT_EQ(ret, FIREWALL_SUCCESS);
}

HWTEST_F(NetFirewallClientTest, AddNetFirewallRule004, TestSize.Level1)
{
    NetManagerExtAccessToken token;
    int32_t ruleId = 0;
    int32_t ret = -1;
    sptr<NetFirewallRule> rule = GetNetFirewallIpV4RuleSptr();
    g_startTimeTest = GetCurrentMilliseconds();
    for (int32_t i = 0; i < MAX_USER_RULE; i++) {
        uint64_t stime = GetCurrentMilliseconds();
        ret = netfirewallClient_.AddNetFirewallRule(rule, ruleId);
        std::cout << "AddNetFirewallRule4 IP " << i + 1 << " ruleId " << ruleId << ", use time : " <<
            GetCurrentMilliseconds() - stime << " ms" << std::endl;
        if (ret != FIREWALL_SUCCESS) {
            EXPECT_EQ(ret, FIREWALL_SUCCESS);
            break;
        }
    }
    g_rowId = ruleId;
    g_endTimeTest = GetCurrentMilliseconds();
    std::cout << "CALL_TEST AddNetFirewallRule4 user " << rule->userId << " call " << MAX_USER_RULE <<
        ", use time : " << g_endTimeTest - g_startTimeTest << " ms" << std::endl;
    EXPECT_EQ(ret, FIREWALL_SUCCESS);
}

/**
 * @tc.name: UpdateNetFirewallRule001
 * @tc.desc: Test NetFirewallClientTest UpdateNetFirewallRule.
 * @tc.type: FUNC
 */
HWTEST_F(NetFirewallClientTest, UpdateNetFirewallRule001, TestSize.Level1)
{
    NetManagerExtAccessToken token;
    int32_t ret = -1;
    sptr<NetFirewallRule> rule = GetNetFirewallRuleSptr();
    rule->userId = 100;
    rule->ruleId = g_rowId;
    g_startTimeTest = GetCurrentMilliseconds();
    for (int32_t i = 0; i < MAX_USER_RULE; i++) {
        ret = netfirewallClient_.UpdateNetFirewallRule(rule);
        std::cout << "UpdateNetFirewallRule " << i + 1 << " ret " << ret << std::endl;
    }
    g_endTimeTest = GetCurrentMilliseconds();
    std::cout << "CALL_TEST UpdateNetFirewallRule user " << rule->userId << " call " << MAX_USER_RULE <<
        ", use time : " << g_endTimeTest - g_startTimeTest << " ms" << std::endl;
    EXPECT_EQ(ret, FIREWALL_SUCCESS);
}

/**
 * @tc.name: GetAllNetFirewallRule001
 * @tc.desc: Test NetFirewallClientTest GetNetFirewallRules.
 * @tc.type: FUNC
 */
HWTEST_F(NetFirewallClientTest, GetAllNetFirewallRule001, TestSize.Level1)
{
    NetManagerExtAccessToken token;
    int32_t userId = 100;
    int32_t ret = -1;
    std::vector<NetFirewallRule> ruleList;
    sptr<RequestParam> param = new (std::nothrow) RequestParam();
    param->page = 0;
    param->pageSize = 5;
    param->orderType = NetFirewallOrderType::ORDER_ASC;
    sptr<FirewallRulePage> info = new (std::nothrow) FirewallRulePage();
    g_startTimeTest = GetCurrentMilliseconds();
    for (int32_t i = 0; i < MAX_USER_RULE; i++) {
        ret = netfirewallClient_.GetNetFirewallRules(userId, param, info);
        std::cout << "GetAllNetFirewallRule " << i + 1 << " page=" << param->page << std::endl;
        info->data.clear();
        if (param->page >= info->totalPage) {
            param->page = 0;
        } else {
            param->page += 1;
        }
    }
    g_endTimeTest = GetCurrentMilliseconds();
    std::cout << "CALL_TEST GetAllNetFirewallRule user " << userId << " call " << MAX_USER_RULE << ", use time : " <<
        g_endTimeTest - g_startTimeTest << " ms" << std::endl;
    EXPECT_EQ(ret, FIREWALL_SUCCESS);
}

/**
 * @tc.name: GetAllNetFirewallRule002
 * @tc.desc: Test NetFirewallClientTest GetNetFirewallRules.
 * @tc.type: FUNC
 */
HWTEST_F(NetFirewallClientTest, GetAllNetFirewallRule002, TestSize.Level1)
{
    int32_t userId = 102;
    sptr<RequestParam> param = new (std::nothrow) RequestParam();
    param->page = 0;
    param->pageSize = 5;
    param->orderType = NetFirewallOrderType::ORDER_DESC;
    sptr<FirewallRulePage> info = new (std::nothrow) FirewallRulePage();
    int32_t ret = netfirewallClient_.GetNetFirewallRules(userId, param, info);

    EXPECT_EQ(ret, FIREWALL_ERR_PERMISSION_DENIED);
}

/**
 * @tc.name: GetNetFirewallRule001
 * @tc.desc: Test NetFirewallClientTest GetNetFirewallRule.
 * @tc.type: FUNC
 */
HWTEST_F(NetFirewallClientTest, GetNetFirewallRule001, TestSize.Level1)
{
    NetManagerExtAccessToken token;
    int32_t ruleId = 1;
    int32_t userId = 100;
    NetFirewallRuleManager::GetInstance().GetAllRuleConstraint(userId);
    ruleId = NetFirewallRuleManager::GetInstance().allUserRule_;
    int32_t ret = -1;
    sptr<NetFirewallRule> rule = new (std::nothrow) NetFirewallRule();
    rule->ruleId = ruleId;
    g_startTimeTest = GetCurrentMilliseconds();
    for (int32_t i = 0; i < MAX_USER_RULE; i++) {
        ret = netfirewallClient_.GetNetFirewallRule(userId, ruleId, rule);
        std::cout << "GetNetFirewallRule " << i + 1 << " ruleId " << rule->ruleId << std::endl;
    }
    g_endTimeTest = GetCurrentMilliseconds();
    std::cout << "CALL_TEST GetNetFirewallRule user " << userId << " call " << MAX_USER_RULE << ", use time : " <<
        g_endTimeTest - g_startTimeTest << " ms" << std::endl;
    if (ruleId == 0) {
        EXPECT_EQ(ret, FIREWALL_ERR_NO_RULE);
    } else {
        EXPECT_EQ(ret, FIREWALL_SUCCESS);
    }
}

/**
 * @tc.name: GetInterceptRecords
 * @tc.desc: Test NetFirewallClientTest GetInterceptRecords.
 * @tc.type: FUNC
 */
HWTEST_F(NetFirewallClientTest, GetInterceptRecord001, TestSize.Level1)
{
    NetManagerExtAccessToken token;
    int32_t userId = 100;
    int32_t ret = -1;
    sptr<RequestParam> param = new (std::nothrow) RequestParam();
    param->page = 0;
    param->pageSize = 5;
    param->orderType = NetFirewallOrderType::ORDER_ASC;
    sptr<InterceptRecordPage> info = new (std::nothrow) InterceptRecordPage();
    g_startTimeTest = GetCurrentMilliseconds();
    for (int32_t i = 0; i < MAX_USER_RULE; i++) {
        ret = netfirewallClient_.GetInterceptRecords(userId, param, info);
        std::cout << "GetInterceptRecord " << i + 1 << " page=" << param->page << std::endl;
        info->data.clear();
        if (param->page >= info->totalPage) {
            param->page = 0;
        } else {
            param->page += 1;
        }
    }
    g_endTimeTest = GetCurrentMilliseconds();
    std::cout << "CALL_TEST GetInterceptRecord user " << userId << " call " << MAX_USER_RULE << ", use time : " <<
        g_endTimeTest - g_startTimeTest << " ms" << std::endl;
    EXPECT_EQ(ret, FIREWALL_SUCCESS);
}

/**
 * @tc.name: DeleteNetFirewallRule001
 * @tc.desc: Test NetFirewallClientTest DeleteNetFirewallRule.
 * @tc.type: FUNC
 */
HWTEST_F(NetFirewallClientTest, DeleteNetFirewallRule001, TestSize.Level1)
{
    NetManagerExtAccessToken token;
    int32_t userId = 100;
    int32_t ruleId = 0;
    NetFirewallRuleManager::GetInstance().GetAllRuleConstraint(userId);
    ruleId = NetFirewallRuleManager::GetInstance().allUserRule_;
    int32_t ret = -1;
    g_startTimeTest = GetCurrentMilliseconds();
    for (int32_t i = 0; i < MAX_USER_RULE; i++) {
        ++ruleId;
        ret = netfirewallClient_.DeleteNetFirewallRule(userId, ruleId);
        std::cout << "DeleteNetFirewallRule " << i + 1 << " ret " << ret << std::endl;
    }
    g_endTimeTest = GetCurrentMilliseconds();
    std::cout << "CALL_TEST DeleteNetFirewallRule user " << ruleId << " call " << MAX_USER_RULE << ", use time : " <<
        g_endTimeTest - g_startTimeTest << " ms" << std::endl;
    EXPECT_EQ(ret, FIREWALL_ERR_NO_RULE);
}

HWTEST_F(NetFirewallClientTest, OnLoadSystemAbility001, TestSize.Level1)
{
    int32_t systemAbilityId = 0;
    DelayedSingleton<NetFirewallLoadCallback>::GetInstance()->OnLoadSystemAbilityFail(systemAbilityId);
    auto ret = DelayedSingleton<NetFirewallLoadCallback>::GetInstance()->IsFailed();
    EXPECT_EQ(ret, true);
}

HWTEST_F(NetFirewallClientTest, OnRemoteDied001, TestSize.Level0)
{
    NetManagerExtAccessToken token;
    wptr<IRemoteObject> remote = nullptr;
    sptr<NetFirewallPolicy> status = new (std::nothrow) NetFirewallPolicy();
    int32_t ret = netfirewallClient_.GetNetFirewallPolicy(USER_ID1, status);
    netfirewallClient_.OnRemoteDied(remote);
    wptr<IRemoteObject> remote1 = netfirewallClient_.netfirewallService_->AsObject();
    netfirewallClient_.OnRemoteDied(remote1);
    sptr<IRemoteObject::DeathRecipient> deathRec =
        new (std::nothrow) NetFirewallClient::MonitorPcfirewallServiceDead(netfirewallClient_);
    deathRec->OnRemoteDied(remote1);
    EXPECT_EQ(ret, FIREWALL_SUCCESS);
}

HWTEST_F(NetFirewallClientTest, GetProxy001, TestSize.Level0)
{
    sptr<INetFirewallService> result = netfirewallClient_.GetProxy();
    EXPECT_NE(result, nullptr);
}

HWTEST_F(NetFirewallClientTest, RestartNetFirewallManagerSysAbility001, TestSize.Level0)
{
    bool result = netfirewallClient_.RestartNetFirewallManagerSysAbility();
    EXPECT_EQ(result, true);
}

HWTEST_F(NetFirewallClientTest, LoadSaOnDemand001, TestSize.Level0)
{
    sptr<IRemoteObject> result = netfirewallClient_.LoadSaOnDemand();
    EXPECT_NE(result, nullptr);
}
} // namespace NetManagerStandard
} // namespace OHOS

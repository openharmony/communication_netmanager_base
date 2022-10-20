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

#include <chrono>
#include <condition_variable>
#include <gtest/gtest.h>
#include <mutex>
#include <thread>

#include "net_mgr_log_wrapper.h"
#include "net_policy_callback.h"
#include "net_policy_callback_test.h"
#include "net_policy_client.h"
#include "net_policy_constants.h"
#include "net_policy_inner_define.h"
#include "net_policy_rule.h"
#include "net_policy_traffic.h"

namespace OHOS {
namespace NetManagerStandard {
const std::string TEST_STRING_PERIODDURATION = "M1";
const std::string ICCID_1 = "sim_abcdefg_1";
const std::string ICCID_2 = "sim_abcdefg_2";
constexpr uint32_t TEST_UID1 = 101;
constexpr uint32_t TEST_WARNING_BYTES_1 = 321;
constexpr uint32_t TEST_LIMIT_BYTES_1 = 4321;
constexpr uint32_t TEST_WARNING_BYTES_2 = 123;
constexpr uint32_t TEST_LIMIT_BYTES_2 = 1234;
constexpr uint32_t TEST_LAST_WARNING_REMIND_1 = 7654321;
constexpr uint32_t TEST_LAST_LIMIT_REMIND_1 = 87654321;
constexpr uint32_t TEST_LAST_WARNING_REMIND_2 = 1234567;
constexpr uint32_t TEST_LAST_LIMIT_REMIND_2 = 12345678;

std::mutex g_callbackMutex;
std::condition_variable g_cv;

int32_t g_callbackUid = -1;
int32_t g_callbackPolicy = -1;
int32_t g_callbackRule = -1;
int32_t g_callbackQuotaPolicySize = -1;
int32_t g_callbackIfacesSize = -1;
bool g_callbackBackgroundPolicy = false;

std::shared_ptr<NetPolicyCallback> netPolicyCallback_ = nullptr;
std::shared_ptr<NetPolicyRule> netPolicyRuleCb_ = nullptr;
std::shared_ptr<NetPolicyTraffic> netPolicyTrafficCb_ = nullptr;

using namespace testing::ext;

class INetPolicyCallbackImpl : public IRemoteStub<INetPolicyCallback> {
public:
    int32_t NetUidPolicyChange(uint32_t uid, uint32_t policy)
    {
        g_callbackUid = uid;
        g_callbackPolicy = policy;
        g_cv.notify_all();
        return 0;
    }

    int32_t NetUidRuleChange(uint32_t uid, uint32_t rule)
    {
        g_callbackUid = uid;
        g_callbackRule = rule;
        g_cv.notify_all();
        return 0;
    }

    int32_t NetQuotaPolicyChange(const std::vector<NetQuotaPolicy> &quotaPolicies)
    {
        g_callbackQuotaPolicySize = quotaPolicies.size();
        g_cv.notify_all();
        return 0;
    }

    int32_t NetStrategySwitch(const std::string &iccid, bool enable)
    {
        return 0;
    }

    int32_t NetMeteredIfacesChange(std::vector<std::string> &ifaces)
    {
        g_callbackIfacesSize = ifaces.size();
        g_cv.notify_all();
        return 0;
    }

    int32_t NetBackgroundPolicyChange(bool isBackgroundPolicyAllow)
    {
        g_callbackBackgroundPolicy = isBackgroundPolicyAllow;
        g_cv.notify_all();
        return 0;
    }
};

class NetPolicyCallbackUTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    sptr<INetPolicyCallbackImpl> GetINetPolicyCallbackSample() const;
};

void NetPolicyCallbackUTest::SetUpTestCase()
{
    netPolicyCallback_ = DelayedSingleton<NetPolicyCallback>::GetInstance();
    netPolicyRuleCb_ = std::make_shared<NetPolicyRule>();
    netPolicyTrafficCb_ = std::make_shared<NetPolicyTraffic>();
}

void NetPolicyCallbackUTest::TearDownTestCase() {}

void NetPolicyCallbackUTest::SetUp() {}

void NetPolicyCallbackUTest::TearDown()
{
    netPolicyRuleCb_->TransPolicyToRule(TEST_UID1, NetUidPolicy::NET_POLICY_NONE);
}

void SetFirstNetQuotaPolicy(std::vector<NetQuotaPolicy> &quotaPolicies)
{
    NetQuotaPolicy quotaPolicy1;
    quotaPolicy1.iccid = ICCID_1;
    quotaPolicy1.periodDuration = "M1"; // M1: First day of the month.
    quotaPolicy1.netType = NetBearType::BEARER_CELLULAR;
    quotaPolicy1.warningBytes = TEST_WARNING_BYTES_1;
    quotaPolicy1.limitBytes = TEST_LIMIT_BYTES_1;
    quotaPolicy1.lastWarningRemind = TEST_LAST_WARNING_REMIND_1;
    quotaPolicy1.lastLimitRemind = TEST_LAST_LIMIT_REMIND_1;
    quotaPolicy1.metered = true;
    quotaPolicy1.limitAction = LimitAction::LIMIT_ACTION_AUTO_BILL;
    quotaPolicies.push_back(quotaPolicy1);
}

void SetSecondNetQuotaPolicy(std::vector<NetQuotaPolicy> &quotaPolicies)
{
    NetQuotaPolicy quotaPolicy2;
    quotaPolicy2.iccid = ICCID_2;
    quotaPolicy2.periodDuration = "Y1";  // y1: First day of the year.
    quotaPolicy2.netType = NetBearType::BEARER_CELLULAR;
    quotaPolicy2.warningBytes = TEST_WARNING_BYTES_2;
    quotaPolicy2.limitBytes = TEST_LIMIT_BYTES_2;
    quotaPolicy2.lastWarningRemind = TEST_LAST_WARNING_REMIND_2;
    quotaPolicy2.lastLimitRemind = TEST_LAST_LIMIT_REMIND_2;
    quotaPolicy2.metered = true;
    quotaPolicy2.limitAction = LimitAction::LIMIT_ACTION_DISABLE;
    quotaPolicies.push_back(quotaPolicy2);
}

void SetPolicyCallback()
{
    netPolicyRuleCb_->TransPolicyToRule(TEST_UID1, NetUidPolicy::NET_POLICY_ALLOW_METERED_BACKGROUND);
}

/**
 * @tc.name: NetPolicyCallback001
 * @tc.desc: Test NetPolicyCallback NetUidPolicyChange.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyCallbackUTest, NetPolicyCallback001, TestSize.Level1)
{
    sptr<INetPolicyCallbackImpl> callback = new INetPolicyCallbackImpl();
    netPolicyCallback_->RegisterNetPolicyCallback(callback);
    std::thread setPolicyCallback(SetPolicyCallback);

    std::unique_lock<std::mutex> lck(g_callbackMutex);
    g_cv.wait_for(lck, std::chrono::seconds(10));
    setPolicyCallback.join();

    std::cout << "g_callbackUid:" << g_callbackUid << std::endl;
    std::cout << "g_callbackPolicy:" << g_callbackPolicy << std::endl;
    ASSERT_EQ(g_callbackUid, TEST_UID1);
    ASSERT_EQ(g_callbackPolicy, 1);
    netPolicyCallback_->UnregisterNetPolicyCallback(callback);
}

void SetPolicyCallback2()
{
    netPolicyRuleCb_->SetBackgroundPolicy(false);
    netPolicyRuleCb_->TransPolicyToRule(TEST_UID1, NetUidPolicy::NET_POLICY_ALLOW_METERED_BACKGROUND);
}

/**
 * @tc.name: NetPolicyCallback002
 * @tc.desc: Test NetPolicyCallback NetUidRuleChange.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyCallbackUTest, NetPolicyCallback002, TestSize.Level1)
{
    sptr<INetPolicyCallbackImpl> callback = new INetPolicyCallbackImpl();
    netPolicyCallback_->RegisterNetPolicyCallback(callback);
    std::thread setPolicyCallback2(SetPolicyCallback2);

    std::unique_lock<std::mutex> lck(g_callbackMutex);
    g_cv.wait_for(lck, std::chrono::seconds(10));
    setPolicyCallback2.join();

    std::cout << "g_callbackUid:" << g_callbackUid << std::endl;
    std::cout << "g_callbackRule:" << g_callbackRule << std::endl;
    ASSERT_EQ(g_callbackUid, TEST_UID1);
    netPolicyCallback_->UnregisterNetPolicyCallback(callback);
}

void SetQuotaPolicy()
{
    std::vector<NetQuotaPolicy> quotaPolicies;
    SetFirstNetQuotaPolicy(quotaPolicies);

    netPolicyTrafficCb_->UpdateQuotaPolicies(quotaPolicies);
}

/**
 * @tc.name: NetPolicyCallback003
 * @tc.desc: Test NetPolicyCallback NetQuotaPolicyChange.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyCallbackUTest, NetPolicyCallback003, TestSize.Level1)
{
    sptr<INetPolicyCallbackImpl> callback = new INetPolicyCallbackImpl();
    netPolicyCallback_->RegisterNetPolicyCallback(callback);
    std::thread setQuotaPolicy(SetQuotaPolicy);

    std::unique_lock<std::mutex> lck(g_callbackMutex);
    g_cv.wait_for(lck, std::chrono::seconds(10));
    setQuotaPolicy.join();

    std::cout << "g_callbackQuotaPolicySize:" << g_callbackQuotaPolicySize << std::endl;
    ASSERT_TRUE(g_callbackQuotaPolicySize > 0);
    netPolicyCallback_->UnregisterNetPolicyCallback(callback);
}

void SetQuotaPolicy2()
{
    std::vector<NetQuotaPolicy> quotaPolicies;
    SetFirstNetQuotaPolicy(quotaPolicies);
    SetSecondNetQuotaPolicy(quotaPolicies);
    netPolicyTrafficCb_->UpdateQuotaPolicies(quotaPolicies);
}

/**
 * @tc.name: NetPolicyCallback004
 * @tc.desc: Test NetPolicyCallback NetMeteredIfacesChange.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyCallbackUTest, NetPolicyCallback004, TestSize.Level1)
{
    sptr<INetPolicyCallbackImpl> callback = new INetPolicyCallbackImpl();
    netPolicyCallback_->RegisterNetPolicyCallback(callback);
    std::thread setQuotaPolicy2(SetQuotaPolicy2);

    std::unique_lock<std::mutex> lck(g_callbackMutex);
    g_cv.wait_for(lck, std::chrono::seconds(10));
    setQuotaPolicy2.join();

    std::cout << "g_callbackIfacesSize:" << g_callbackIfacesSize << std::endl;
    ASSERT_TRUE(g_callbackIfacesSize >= 0);
    netPolicyCallback_->UnregisterNetPolicyCallback(callback);
}

void SetBackgroundPolicy()
{
    netPolicyRuleCb_->SetBackgroundPolicy(true);
}

/**
 * @tc.name: NetPolicyCallback005
 * @tc.desc: Test NetPolicyCallback NetBackgroundPolicyChange.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyCallbackUTest, NetPolicyCallback005, TestSize.Level1)
{
    sptr<INetPolicyCallbackImpl> callback = new INetPolicyCallbackImpl();
    netPolicyCallback_->RegisterNetPolicyCallback(callback);
    std::thread setBackgroundPolicy(SetBackgroundPolicy);

    std::unique_lock<std::mutex> lck(g_callbackMutex);
    g_cv.wait_for(lck, std::chrono::seconds(10));
    setBackgroundPolicy.join();

    std::cout << "g_callbackBackgroundPolicy:" << g_callbackBackgroundPolicy << std::endl;
    ASSERT_TRUE(g_callbackBackgroundPolicy == true);
    netPolicyCallback_->UnregisterNetPolicyCallback(callback);
}
} // namespace NetManagerStandard
} // namespace OHOS

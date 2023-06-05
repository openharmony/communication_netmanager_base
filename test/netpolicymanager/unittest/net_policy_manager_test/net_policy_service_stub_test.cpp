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

#include <vector>

#include <gtest/gtest.h>

#ifdef GTEST_API_
#define private public
#define protected public
#endif
#include "net_policy_service_stub.h"

namespace OHOS {
namespace NetManagerStandard {
namespace {
#define DTEST_LOG std::cout << __func__ << ":" << __LINE__ << ":"
constexpr const char *ETH_IFACE_NAME = "lo";
constexpr int32_t TEST_UID = 1010;
class MockNetPolicyServiceStubTest : public NetPolicyServiceStub {
public:
    MockNetPolicyServiceStubTest() = default;
    ~MockNetPolicyServiceStubTest() = default;
    int32_t SetPolicyByUid(uint32_t uid, uint32_t policy) override
    {
        return 0;
    }

    int32_t GetPolicyByUid(uint32_t uid, uint32_t &policy) override
    {
        return 0;
    }

    int32_t GetUidsByPolicy(uint32_t policy, std::vector<uint32_t> &uids) override
    {
        return 0;
    }

    int32_t IsUidNetAllowed(uint32_t uid, bool metered, bool &isAllowed) override
    {
        return 0;
    }

    int32_t IsUidNetAllowed(uint32_t uid, const std::string &ifaceName, bool &isAllowed) override
    {
        return 0;
    }

    int32_t RegisterNetPolicyCallback(const sptr<INetPolicyCallback> &callback) override
    {
        return 0;
    }

    int32_t UnregisterNetPolicyCallback(const sptr<INetPolicyCallback> &callback) override
    {
        return 0;
    }

    int32_t SetNetQuotaPolicies(const std::vector<NetQuotaPolicy> &quotaPolicies) override
    {
        return 0;
    }

    int32_t GetNetQuotaPolicies(std::vector<NetQuotaPolicy> &quotaPolicies) override
    {
        return 0;
    }

    int32_t UpdateRemindPolicy(int32_t netType, const std::string &iccid, uint32_t remindType) override
    {
        return 0;
    }

    int32_t SetDeviceIdleAllowedList(const std::vector<uint32_t> &uids, bool isAllowed) override
    {
        return 0;
    }

    int32_t GetDeviceIdleAllowedList(std::vector<uint32_t> &uids) override
    {
        return 0;
    }

    int32_t SetDeviceIdlePolicy(bool enable) override
    {
        return 0;
    }

    int32_t ResetPolicies(const std::string &iccid) override
    {
        return 0;
    }

    int32_t SetBackgroundPolicy(bool isAllowed) override
    {
        return 0;
    }

    int32_t GetBackgroundPolicy(bool &backgroundPolicy) override
    {
        return 0;
    }

    int32_t GetBackgroundPolicyByUid(uint32_t uid, uint32_t &backgroundPolicyOfUid) override
    {
        return 0;
    }

    int32_t GetPowerSaveAllowedList(std::vector<uint32_t> &uids) override
    {
        return 0;
    }

    int32_t SetPowerSaveAllowedList(const std::vector<uint32_t> &uids, bool isAllowed) override
    {
        return 0;
    }

    int32_t SetPowerSavePolicy(bool enable) override
    {
        return 0;
    }

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        bool byPassPolicyPermission = false;
        if (!data.ReadBool(byPassPolicyPermission)) {
            return NETMANAGER_ERR_READ_DATA_FAIL;
        }

        if (!byPassPolicyPermission) {
            return NetPolicyServiceStub::OnRemoteRequest(code, data, reply, option);
        }

        auto itFunc = memberFuncMap_.find(code);
        int32_t result = NETMANAGER_SUCCESS;
        if (itFunc != memberFuncMap_.end()) {
            auto requestFunc = itFunc->second;
            if (requestFunc != nullptr) {
                handler_->PostSyncTask(
                    [this, &data, &reply, &requestFunc, &result]() { result = (this->*requestFunc)(data, reply); },
                    AppExecFwk::EventQueue::Priority::HIGH);
                return result;
            }
        }

        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
};

} // namespace

using namespace testing::ext;
class NetPolicyServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static inline sptr<NetPolicyServiceStub> instance_ = new (std::nothrow) MockNetPolicyServiceStubTest();
};

void NetPolicyServiceStubTest::SetUpTestCase() {}

void NetPolicyServiceStubTest::TearDownTestCase() { instance_ = nullptr; }

void NetPolicyServiceStubTest::SetUp() {}

void NetPolicyServiceStubTest::TearDown() {}

/**
 * @tc.name: OnRemoteRequestTest001
 * @tc.desc: Test NetPolicyServiceStub OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnRemoteRequestTest001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteBool(false);
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_END, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_ERR_DESCRIPTOR_MISMATCH);
}

/**
 * @tc.name: OnRemoteRequestTest002
 * @tc.desc: Test NetPolicyServiceStub OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnRemoteRequestTest002, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(false);
    if (!data.WriteInterfaceToken(NetPolicyServiceStub::GetDescriptor())) {
        return;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_END, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_ERR_PERMISSION_DENIED);
}

/**
 * @tc.name: OnRemoteRequestTest003
 * @tc.desc: Test NetPolicyServiceStub OnRemoteRequest.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnRemoteRequestTest003, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(false);
    if (!data.WriteInterfaceToken(NetPolicyServiceStub::GetDescriptor())) {
        return;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_SET_POLICY_BY_UID, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_ERR_PERMISSION_DENIED);
}

/**
 * @tc.name: OnSetPolicyByUidTest001
 * @tc.desc: Test NetPolicyServiceStub OnSetPolicyByUid.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnSetPolicyByUidTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    data.WriteUint32(TEST_UID);
    data.WriteUint32(0);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_SET_POLICY_BY_UID, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetPolicyByUidTest001
 * @tc.desc: Test NetPolicyServiceStub OnGetPolicyByUid.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnGetPolicyByUidTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    data.WriteUint32(TEST_UID);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_GET_POLICY_BY_UID, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetUidsByPolicyTest001
 * @tc.desc: Test NetPolicyServiceStub OnGetUidsByPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnGetUidsByPolicyTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    data.WriteUint32(TEST_UID);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_GET_UIDS_BY_POLICY, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnIsUidNetAllowedMeteredTest001
 * @tc.desc: Test NetPolicyServiceStub OnIsUidNetAllowedMetered.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnIsUidNetAllowedMeteredTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    data.WriteUint32(TEST_UID);
    data.WriteBool(true);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_IS_NET_ALLOWED_BY_METERED, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnIsUidNetAllowedIfaceNameTest001
 * @tc.desc: Test NetPolicyServiceStub OnIsUidNetAllowedIfaceName.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnIsUidNetAllowedIfaceNameTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    data.WriteUint32(TEST_UID);
    data.WriteString(ETH_IFACE_NAME);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_IS_NET_ALLOWED_BY_IFACE, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnSetNetQuotaPoliciesTest001
 * @tc.desc: Test NetPolicyServiceStub OnSetNetQuotaPolicies.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnSetNetQuotaPoliciesTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    NetQuotaPolicy quotaPolicy;
    quotaPolicy.title = "test";
    std::vector<NetQuotaPolicy> quotaPolicies;
    quotaPolicies.emplace_back(quotaPolicy);
    NetQuotaPolicy::Marshalling(data, quotaPolicies);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_SET_NET_QUOTA_POLICIES, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetNetQuotaPoliciesTest001
 * @tc.desc: Test NetPolicyServiceStub OnGetNetQuotaPolicies.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnGetNetQuotaPoliciesTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_GET_NET_QUOTA_POLICIES, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnResetPoliciesTest001
 * @tc.desc: Test NetPolicyServiceStub OnResetPolicies.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnResetPoliciesTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    data.WriteString("subscriberId");
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_RESET_POLICIES, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnSetBackgroundPolicyTest001
 * @tc.desc: Test NetPolicyServiceStub OnSetBackgroundPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnSetBackgroundPolicyTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    data.WriteBool(true);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_SET_BACKGROUND_POLICY, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetBackgroundPolicyTest001
 * @tc.desc: Test NetPolicyServiceStub OnGetBackgroundPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnGetBackgroundPolicyTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_GET_BACKGROUND_POLICY, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetBackgroundPolicyByUidTest001
 * @tc.desc: Test NetPolicyServiceStub OnGetBackgroundPolicyByUid.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnGetBackgroundPolicyByUidTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    data.WriteBool(true);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(
        INetPolicyService::CMD_NPS_GET_BACKGROUND_POLICY_BY_UID, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnSnoozePolicyTest001
 * @tc.desc: Test NetPolicyServiceStub OnSnoozePolicy.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnSnoozePolicyTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    data.WriteInt32(0);
    data.WriteString("iccid");
    data.WriteInt32(0);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_UPDATE_REMIND_POLICY, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnSetDeviceIdleAllowedListTest003
 * @tc.desc: Test NetPolicyServiceStub OnSetDeviceIdleAllowedList.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnSetDeviceIdleAllowedListTest003, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    std::vector<uint32_t> uids;
    uids.emplace_back(TEST_UID);
    data.WriteUInt32Vector(uids);
    data.WriteBool(true);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_SET_IDLE_ALLOWED_LIST, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetDeviceIdleAllowedListTest001
 * @tc.desc: Test NetPolicyServiceStub OnGetDeviceIdleAllowedList.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnGetDeviceIdleAllowedListTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_GET_IDLE_ALLOWED_LIST, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnSetDeviceIdlePolicyTest001
 * @tc.desc: Test NetPolicyServiceStub OnSetDeviceIdlePolicy.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnSetDeviceIdlePolicyTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    data.WriteBool(true);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(INetPolicyService::CMD_NPS_SET_DEVICE_IDLE_POLICY, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetPowerSaveAllowedListTest001
 * @tc.desc: Test NetPolicyServiceStub OnGetPowerSaveAllowedList.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnGetPowerSaveAllowedListTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(
        INetPolicyService::CMD_NPS_GET_POWER_SAVE_ALLOWED_LIST, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnSetPowerSaveAllowedListTest001
 * @tc.desc: Test NetPolicyServiceStub OnSetPowerSaveAllowedList.
 * @tc.type: FUNC
 */
HWTEST_F(NetPolicyServiceStubTest, OnSetPowerSaveAllowedListTest001, TestSize.Level1)
{
    MessageParcel data;
    data.WriteBool(true);
    std::vector<uint32_t> uids;
    uids.emplace_back(TEST_UID);
    data.WriteUInt32Vector(uids);
    data.WriteBool(true);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = instance_->OnRemoteRequest(
        INetPolicyService::CMD_NPS_SET_POWER_SAVE_ALLOWED_LIST, data, reply, option);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

} // namespace NetManagerStandard
} // namespace OHOS
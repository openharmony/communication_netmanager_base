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

#include <gtest/gtest.h>

#include "notify_callback_proxy.h"

namespace OHOS {
namespace NetsysNative {
namespace {
using namespace testing::ext;

class MockNetIRemoteObject : public IRemoteObject {
public:
    MockNetIRemoteObject() : IRemoteObject(u"mock_i_remote_object") {}
    ~MockNetIRemoteObject() {}

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }

    bool IsProxyObject() const override
    {
        return true;
    }

    bool CheckObjectLegality() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }

    std::u16string GetObjectDescriptor() const
    {
        std::u16string descriptor = std::u16string();
        return descriptor;
    }
};
} // namespace

class NotifyCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static inline std::shared_ptr<NotifyCallbackProxy> notifyProxy = nullptr;
};

void NotifyCallbackProxyTest::SetUpTestCase()
{
    sptr<IRemoteObject> impl = new (std::nothrow) MockNetIRemoteObject();
    notifyProxy = std::make_shared<NotifyCallbackProxy>(impl);
}

void NotifyCallbackProxyTest::TearDownTestCase() {}

void NotifyCallbackProxyTest::SetUp() {}

void NotifyCallbackProxyTest::TearDown() {}

HWTEST_F(NotifyCallbackProxyTest, OnInterfaceAddressUpdated001, TestSize.Level1)
{
    std::string addr = "192.161.0.5";
    std::string ifName = "test0";
    int flags = 1;
    int scope = 2;
    int32_t ret = notifyProxy->OnInterfaceAddressUpdated(addr, ifName, flags, scope);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(NotifyCallbackProxyTest, OnInterfaceAddressRemoved001, TestSize.Level1)
{
    sptr<IRemoteObject> impl = new (std::nothrow) MockNetIRemoteObject();
    sptr<NotifyCallbackProxy> notifyProxy = new (std::nothrow) NotifyCallbackProxy(impl);
    std::string addr = "192.161.0.5";
    std::string ifName = "test0";
    int flags = 1;
    int scope = 2;
    int32_t ret = notifyProxy->OnInterfaceAddressRemoved(addr, ifName, flags, scope);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(NotifyCallbackProxyTest, OnInterfaceAdded001, TestSize.Level1)
{
    std::string ifName = "test0";
    int32_t ret = notifyProxy->OnInterfaceAdded(ifName);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(NotifyCallbackProxyTest, OnInterfaceRemoved001, TestSize.Level1)
{
    std::string ifName = "test0";
    int32_t ret = notifyProxy->OnInterfaceRemoved(ifName);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(NotifyCallbackProxyTest, OnInterfaceChanged001, TestSize.Level1)
{
    std::string ifName = "test0";
    bool isUp = false;
    int32_t ret = notifyProxy->OnInterfaceChanged(ifName, isUp);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(NotifyCallbackProxyTest, OnInterfaceLinkStateChanged001, TestSize.Level1)
{
    std::string ifName = "test0";
    bool isUp = false;
    int32_t ret = notifyProxy->OnInterfaceLinkStateChanged(ifName, isUp);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(NotifyCallbackProxyTest, OnRouteChanged001, TestSize.Level1)
{
    bool updated = false;
    std::string route = "192.168.0.1";
    std::string gateway = "192.168.0.1";
    std::string ifName = "test0";
    int32_t ret = notifyProxy->OnRouteChanged(updated, route, gateway, ifName);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(NotifyCallbackProxyTest, OnDhcpSuccess001, TestSize.Level1)
{
    sptr<DhcpResultParcel> dhcpResult = new (std::nothrow) DhcpResultParcel;
    dhcpResult->iface_ = "test0";
    dhcpResult->ipAddr_ = "192.168.11.55";
    dhcpResult->gateWay_ = "192.168.10.1";
    dhcpResult->subNet_ = "255.255.255.0";
    int32_t ret = notifyProxy->OnDhcpSuccess(dhcpResult);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(NotifyCallbackProxyTest, OnBandwidthReachedLimit001, TestSize.Level1)
{
    std::string limitName = "limit";
    std::string iface = "test0";
    int32_t ret = notifyProxy->OnBandwidthReachedLimit(limitName, iface);
    EXPECT_EQ(ret, 0);
}
} // namespace nmd
} // namespace OHOS
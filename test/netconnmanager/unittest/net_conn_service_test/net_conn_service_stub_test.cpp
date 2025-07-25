/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "common_net_conn_callback_test.h"
#include "net_conn_service_stub_test.h"
#include "net_interface_callback_stub.h"
#include "netmanager_base_test_security.h"
#include "net_conn_types.h"

namespace OHOS {
namespace NetManagerStandard {
namespace {
constexpr bool TEST_BOOL_VALUE = false;
constexpr int32_t TEST_INT32_VALUE = 1;
constexpr uint32_t TEST_UINT32_VALUE = 1;
constexpr const char *TEST_STRING_VALUE = "test";
constexpr const char *TEST_DOMAIN = "test.com";
} // namespace

class INetFactoryResetCallbackTest : public IRemoteStub<INetFactoryResetCallback> {
public:
    INetFactoryResetCallbackTest() = default;

    int32_t OnNetFactoryReset()
    {
        return 0;
    }
};

using namespace testing::ext;
class NetConnServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static inline std::shared_ptr<NetConnServiceStub> instance_ = std::make_shared<MockNetConnServiceStub>();
    static inline sptr<INetSupplierCallback> supplierCallback_ = new (std::nothrow) NetSupplierCallbackStub();
    static int32_t SendRemoteRequest(MessageParcel &data, ConnInterfaceCode code);
};

void NetConnServiceStubTest::SetUpTestCase() {}

void NetConnServiceStubTest::TearDownTestCase() {}

void NetConnServiceStubTest::SetUp() {}

void NetConnServiceStubTest::TearDown() {}

int32_t NetConnServiceStubTest::SendRemoteRequest(MessageParcel &data, ConnInterfaceCode code)
{
    MessageParcel reply;
    MessageOption option;
    return instance_->OnRemoteRequest(static_cast<uint32_t>(code), data, reply, option);
}

/**
 * @tc.name: OnSystemReadyTest001
 * @tc.desc: Test NetConnServiceStub OnSystemReady.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnSystemReadyTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SYSTEM_READY);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnRegisterNetSupplierTest001
 * @tc.desc: Test NetConnServiceStub OnRegisterNetSupplier.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnRegisterNetSupplierTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REG_NET_SUPPLIER);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnUnregisterNetSupplierTest001
 * @tc.desc: Test NetConnServiceStub OnUnregisterNetSupplier.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnUnregisterNetSupplierTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_UNREG_NETWORK);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnRegisterNetSupplierCallbackTest001
 * @tc.desc: Test NetConnServiceStub OnRegisterNetSupplierCallback.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnRegisterNetSupplierCallbackTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    sptr<INetSupplierCallback> callback = new (std::nothrow) NetSupplierCallbackStubTestCb();
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REGISTER_NET_SUPPLIER_CALLBACK);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnRegisterNetConnCallbackTest001
 * @tc.desc: Test NetConnServiceStub OnRegisterNetConnCallback.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnRegisterNetConnCallbackTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    sptr<INetConnCallbackTest> callback = new (std::nothrow) INetConnCallbackTest();
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REGISTER_NET_CONN_CALLBACK);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnUnregisterNetConnCallbackTest001
 * @tc.desc: Test NetConnServiceStub OnUnregisterNetConnCallback.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnUnregisterNetConnCallbackTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    sptr<INetConnCallbackTest> callback = new (std::nothrow) INetConnCallbackTest();
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_UNREGISTER_NET_CONN_CALLBACK);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnUpdateNetStateForTest001
 * @tc.desc: Test NetConnServiceStub OnUpdateNetStateForTest.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnUpdateNetStateForTest001, TestSize.Level1)
{
    sptr<NetSpecifier> netSpecifier = new (std::nothrow) NetSpecifier();
    if (netSpecifier == nullptr) {
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!netSpecifier->Marshalling(data)) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_UPDATE_NET_STATE_FOR_TEST);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnUpdateNetSupplierInfoTest001
 * @tc.desc: Test NetConnServiceStub OnUpdateNetSupplierInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnUpdateNetSupplierInfoTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    sptr<NetSupplierInfo> netSupplierInfo = new (std::nothrow) NetSupplierInfo();
    if (netSupplierInfo == nullptr) {
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    if (!netSupplierInfo->Marshalling(data)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_NET_SUPPLIER_INFO);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnUpdateNetLinkInfoTest001
 * @tc.desc: Test NetConnServiceStub OnUpdateNetLinkInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnUpdateNetLinkInfoTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    sptr<NetLinkInfo> netLinkInfo = new (std::nothrow) NetLinkInfo();
    if (netLinkInfo == nullptr) {
        return;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    if (!netLinkInfo->Marshalling(data)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_NET_LINK_INFO);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnNetDetectionTest001
 * @tc.desc: Test NetConnServiceStub OnNetDetection.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnNetDetectionTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_NET_DETECTION);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetIfaceNamesTest001
 * @tc.desc: Test NetConnServiceStub OnGetIfaceNames.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetIfaceNamesTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_IFACE_NAMES);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetIfaceNameByTypeTest001
 * @tc.desc: Test NetConnServiceStub OnGetIfaceNameByType.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetIfaceNameByTypeTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_IFACENAME_BY_TYPE);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetDefaultNetTest001
 * @tc.desc: Test NetConnServiceStub OnGetDefaultNet.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetDefaultNetTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GETDEFAULTNETWORK);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnHasDefaultNetTest001
 * @tc.desc: Test NetConnServiceStub OnHasDefaultNet.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnHasDefaultNetTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_HASDEFAULTNET);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetSpecificNetTest001
 * @tc.desc: Test NetConnServiceStub OnGetSpecificNet.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetSpecificNetTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_SPECIFIC_NET);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetSpecificNetByIdentTest001
 * @tc.desc: Test NetConnServiceStub OnGetSpecificNetByIdent.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetSpecificNetByIdentTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_SPECIFIC_NET_BY_IDENT);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetAllNetsTest001
 * @tc.desc: Test NetConnServiceStub OnGetAllNets.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetAllNetsTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_ALL_NETS);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetSpecificUidNetTest001
 * @tc.desc: Test NetConnServiceStub OnGetSpecificUidNet.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetSpecificUidNetTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_SPECIFIC_UID_NET);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetConnectionPropertiesTest001
 * @tc.desc: Test NetConnServiceStub OnGetConnectionProperties.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetConnectionPropertiesTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_CONNECTION_PROPERTIES);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetNetCapabilitiesTest001
 * @tc.desc: Test NetConnServiceStub OnGetNetCapabilities.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetNetCapabilitiesTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_NET_CAPABILITIES);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetAddressesByNameTest001
 * @tc.desc: Test NetConnServiceStub OnGetAddressesByName.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetAddressesByNameTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_ADDRESSES_BY_NAME);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetAddressByNameTest001
 * @tc.desc: Test NetConnServiceStub OnGetAddressByName.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetAddressByNameTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_ADDRESS_BY_NAME);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetIfaceNameIdentMapsTest001
 * @tc.desc: Test NetConnServiceStub GetIfaceNameIdentMaps.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetIfaceNameIdentMapsTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(0)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_GET_IFACENAME_IDENT_MAPS);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnBindSocketTest001
 * @tc.desc: Test NetConnServiceStub OnBindSocket.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnBindSocketTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_BIND_SOCKET);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnSetAirplaneModeTest001
 * @tc.desc: Test NetConnServiceStub OnSetAirplaneMode.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnSetAirplaneModeTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteBool(TEST_BOOL_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_AIRPLANE_MODE);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnIsDefaultNetMeteredTest001
 * @tc.desc: Test NetConnServiceStub OnIsDefaultNetMetered.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnIsDefaultNetMeteredTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_IS_DEFAULT_NET_METERED);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnSetGlobalHttpProxyTest001
 * @tc.desc: Test NetConnServiceStub OnSetGlobalHttpProxy.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnSetGlobalHttpProxyTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    HttpProxy httpProxy = { TEST_DOMAIN, 8080, {} };
    if (!httpProxy.Marshalling(data)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_GLOBAL_HTTP_PROXY);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetGlobalHttpProxyTest001
 * @tc.desc: Test NetConnServiceStub OnGetGlobalHttpProxy.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetGlobalHttpProxyTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_GLOBAL_HTTP_PROXY);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetDefaultHttpProxyTest001
 * @tc.desc: Test NetConnServiceStub OnGetDefaultHttpProxy.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetDefaultHttpProxyTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_DEFAULT_HTTP_PROXY);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetNetIdByIdentifierTest001
 * @tc.desc: Test NetConnServiceStub OnGetNetIdByIdentifier.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetNetIdByIdentifierTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_NET_ID_BY_IDENTIFIER);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnSetAppNetTest001
 * @tc.desc: Test NetConnServiceStub OnSetAppNet.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnSetAppNetTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_APP_NET);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnRegisterNetInterfaceCallbackTest001
 * @tc.desc: Test NetConnServiceStub OnRegisterNetInterfaceCallback.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnRegisterNetInterfaceCallbackTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    sptr<INetInterfaceStateCallback> callback = new (std::nothrow) NetInterfaceStateCallbackStub();
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REGISTER_NET_INTERFACE_CALLBACK);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
    ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_UNREGISTER_NET_INTERFACE_CALLBACK);
    EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
}

HWTEST_F(NetConnServiceStubTest, OnUnregisterNetInterfaceCallback001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    sptr<INetInterfaceStateCallback> callback = new (std::nothrow) NetInterfaceStateCallbackStub();
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_UNREGISTER_NET_INTERFACE_CALLBACK);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnAddNetworkRouteTest001
 * @tc.desc: Test NetConnServiceStub OnAddNetworkRoute.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnAddNetworkRouteTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_ADD_NET_ROUTE);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnRemoveNetworkRouteTest001
 * @tc.desc: Test NetConnServiceStub OnRemoveNetworkRoute.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnRemoveNetworkRouteTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REMOVE_NET_ROUTE);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnAddInterfaceAddressTest001
 * @tc.desc: Test NetConnServiceStub OnAddInterfaceAddress.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnAddInterfaceAddressTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_ADD_NET_ADDRESS);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnDelInterfaceAddressTest001
 * @tc.desc: Test NetConnServiceStub OnDelInterfaceAddress.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnDelInterfaceAddressTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REMOVE_NET_ADDRESS);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnAddStaticArpTest001
 * @tc.desc: Test NetConnServiceStub OnAddStaticArp.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnAddStaticArpTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_ADD_STATIC_ARP);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnDelStaticArpTest001
 * @tc.desc: Test NetConnServiceStub OnDelStaticArp.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnDelStaticArpTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_DEL_STATIC_ARP);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnAddStaticIpv6Test001
 * @tc.desc: Test NetConnServiceStub OnAddStaticIpv6.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnAddStaticIpv6Test001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = instance_->OnAddStaticIpv6Addr(data, reply);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnDelStaticIpv6Test001
 * @tc.desc: Test NetConnServiceStub OnDelStaticIpv6.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnDelStaticIpv6Test001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = instance_->OnDelStaticIpv6Addr(data, reply);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnRegisterSlotTypeTest001
 * @tc.desc: Test NetConnServiceStub OnRegisterSlotType.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnRegisterSlotTypeTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }

    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REGISTER_SLOT_TYPE);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetSlotTypeTest001
 * @tc.desc: Test NetConnServiceStub OnGetSlotType.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetSlotTypeTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_SLOT_TYPE);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnFactoryResetNetworkTest001
 * @tc.desc: Test NetConnServiceStub OnFactoryResetNetwork.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnFactoryResetNetworkTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_FACTORYRESET_NETWORK);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnRegisterNetFactoryResetCallbackTest001
 * @tc.desc: Test NetConnServiceStub OnRegisterNetFactoryResetCallback.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnRegisterNetFactoryResetCallbackTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    sptr<INetFactoryResetCallbackTest> callback = new (std::nothrow) INetFactoryResetCallbackTest();
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REGISTER_NET_FACTORYRESET_CALLBACK);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnIsPreferCellularUrlTest001
 * @tc.desc: Test NetConnServiceStub OnIsPreferCellularUrl.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnIsPreferCellularUrlTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_IS_PREFER_CELLULAR_URL);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnUpdateSupplierScore001
 * @tc.desc: Test NetConnServiceStub OnUpdateSupplierScore001
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnUpdateSupplierScore001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    uint32_t supplierId = 100;
    if (!data.WriteUint32(supplierId)) {
        return;
    }
    if (!data.WriteUint32(QUALITY_GOOD_STATE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_UPDATE_SUPPLIER_SCORE);
    EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: GetDefaultSupplierId001
 * @tc.desc: Test NetConnServiceStub GetDefaultSupplierId001.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, GetDefaultSupplierId001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    uint32_t bearerType = 0;
    if (!data.WriteUint32(bearerType)) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    uint32_t supplierId = 100;
    if (!data.WriteUint32(supplierId)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_SPECIFIC_SUPPLIER_ID);
    EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: OnRequestNetConnectionBySpecifierTest001
 * @tc.desc: Test NetConnServiceStub OnRequestNetConnection.
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnRequestNetConnectionBySpecifierTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    sptr<NetSpecifier> netSpecifier = new (std::nothrow) NetSpecifier();
    if (netSpecifier == nullptr) {
        return;
    }

    if (!netSpecifier->Marshalling(data)) {
        return;
    }

    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }

    sptr<INetConnCallbackTest> callback = new (std::nothrow) INetConnCallbackTest();
    if (!data.WriteRemoteObject(callback->AsObject().GetRefPtr())) {
        return;
    }

    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REQUEST_NET_CONNECTION);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnEnableVnicNetwork001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    sptr<NetLinkInfo> netLinkInfo = new (std::nothrow) NetLinkInfo();
    if (netLinkInfo == nullptr) {
        return;
    }

    if (!netLinkInfo->Marshalling(data)) {
        return;
    }

    std::set<int32_t> uids;
    if (!data.WriteInt32(uids.size())) {
        return;
    }

    for (const auto &uid: uids) {
        if (!data.WriteInt32(uid)) {
            return;
        }
    }

    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_ENABLE_VNIC_NET_WORK);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnDisableVnicNetwork001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_DISABLE_VNIC_NET_WORK);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, CloseSocketsUid001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t netId = 1;
    if (!data.WriteInt32(netId)) {
        return;
    }
    uint32_t uid = 1;
    if (!data.WriteUint32(uid)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_CLOSE_SOCKETS_UID);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, CloseSocketsUid002, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_CLOSE_SOCKETS_UID);
    EXPECT_EQ(ret, NETMANAGER_ERR_READ_DATA_FAIL);
}

HWTEST_F(NetConnServiceStubTest, CloseSocketsUid003, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t netId = 1;
    if (!data.WriteInt32(netId)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_CLOSE_SOCKETS_UID);
    EXPECT_EQ(ret, NETMANAGER_ERR_READ_DATA_FAIL);
}

HWTEST_F(NetConnServiceStubTest, SetInterfaceUpDownTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_INTERFACE_UP);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_INTERFACE_DOWN);
    EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
}

HWTEST_F(NetConnServiceStubTest, SetInterfaceUpDownTest002, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_INTERFACE_DOWN);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, SetNetInterfaceIpAddressTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }

    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_INTERFACE_IP_ADDRESS);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnUpdateNetCaps, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    if (!data.WriteUint32(TEST_UINT32_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_UPDATE_NET_CAPS);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnSetPacUrl
 * @tc.desc: Test NetConnServiceStub.OnSetPacUrl
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnSetPacUrlTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_PAC_URL);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}
 
/**
 * @tc.name: OnSetPacUrl
 * @tc.desc: Test NetConnServiceStub.OnSetPacUrl
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnSetPacUrlTest002, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_PAC_URL);
    EXPECT_EQ(ret, NETMANAGER_ERR_PERMISSION_DENIED);
}
 
/**
 * @tc.name: OnGetPacUrlTest001
 * @tc.desc: Test NetConnServiceStub.OnGetPacUrl
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetPacUrlTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_PAC_URL);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnSetNetExtAttribute
 * @tc.desc: Test NetConnServiceStub.OnSetNetExtAttribute
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnSetNetExtAttributeTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    if (!data.WriteString(TEST_STRING_VALUE)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_NET_EXT_ATTRIBUTE);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: OnGetNetExtAttribute
 * @tc.desc: Test NetConnServiceStub.OnGetNetExtAttribute
 * @tc.type: FUNC
 */
HWTEST_F(NetConnServiceStubTest, OnGetNetExtAttributeTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(TEST_INT32_VALUE)) {
        return;
    }
    std::string str;
    if (!data.WriteString(str)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_NET_EXT_ATTRIBUTE);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnSetAppIsFrozenedTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_APP_IS_FROZENED);
    EXPECT_NE(ret, NETMANAGER_ERR_PARAMETER_ERROR);
}

HWTEST_F(NetConnServiceStubTest, OnEnableAppFrozenedCallbackLimitationTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_ENABLE_APP_FROZENED_CALLBACK_LIMITATION);
    EXPECT_NE(ret, NETMANAGER_ERR_PARAMETER_ERROR);
}

HWTEST_F(NetConnServiceStubTest, OnSetReuseSupplierIdTest001, TestSize.Level1)
{
    NetManagerBaseAccessToken token;
    MessageParcel data;
    uint32_t supplierId = 1;
    uint32_t reuseSupplierId = 2;
    bool isReused = false;
    if (!data.WriteInterfaceToken(NetConnServiceStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(supplierId)) {
        return;
    }
    if (!data.WriteUint32(reuseSupplierId)) {
        return;
    }
    if (!data.WriteBool(isReused)) {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_REUSE_SUPPLIER_ID);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnSetInternetPermissionTest001, TestSize.Level1)
{
    MessageParcel data;
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_SET_INTERNET_PERMISSION);
    EXPECT_NE(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnRegisterNetConnCallbackBySpecifierTest001, TestSize.Level1)
{
    MessageParcel data;
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REGISTER_NET_CONN_CALLBACK_BY_SPECIFIER);
    EXPECT_NE(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnRegisterNetDetectionCallbackTest001, TestSize.Level1)
{
    MessageParcel data;
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REGISTER_NET_DETECTION_RET_CALLBACK);
    EXPECT_NE(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnUnRegisterNetDetectionCallbackTest001, TestSize.Level1)
{
    MessageParcel data;
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_UNREGISTER_NET_DETECTION_RET_CALLBACK);
    EXPECT_NE(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnGetNetInterfaceConfigurationTest001, TestSize.Level1)
{
    MessageParcel data;
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_GET_INTERFACE_CONFIGURATION);
    EXPECT_NE(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnRegisterPreAirplaneCallbackTest001, TestSize.Level1)
{
    MessageParcel data;
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_REGISTER_PREAIRPLANE_CALLBACK);
    EXPECT_NE(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnUnregisterPreAirplaneCallbackTest001, TestSize.Level1)
{
    MessageParcel data;
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_UNREGISTER_PREAIRPLANE_CALLBACK);
    EXPECT_NE(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetConnServiceStubTest, OnQueryTraceRouteTest001, TestSize.Level1)
{
    MessageParcel data;
    if (!data.WriteInt32(TEST_INT32_VALUE))
    {
        return;
    }
    int32_t ret = SendRemoteRequest(data, ConnInterfaceCode::CMD_NM_QUERY_TRACEROUTE);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

} // namespace NetManagerStandard
} // namespace OHOS
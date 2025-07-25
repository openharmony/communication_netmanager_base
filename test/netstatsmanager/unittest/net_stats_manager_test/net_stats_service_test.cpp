/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <ctime>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#ifdef GTEST_API_
#define private public
#define protected public
#endif

#include "net_manager_center.h"
#include "net_stats_callback_test.h"
#include "net_stats_constants.h"
#include "net_stats_service.h"
#include "net_stats_database_defines.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace NetManagerStandard {
using namespace NetStatsDatabaseDefines;
namespace {
#define DTEST_LOG std::cout << __func__ << ":" << __LINE__ << ":"
constexpr const char *ETH_IFACE_NAME = "lo";
constexpr int64_t TEST_UID = 1010;
constexpr int32_t TEST_FD = 2;
static constexpr uint64_t TEST_COOKIE = 1;
void GetIfaceNamesFromManager(std::list<std::string> &ifaceNames)
{
    NetManagerCenter::GetInstance().GetIfaceNames(BEARER_CELLULAR, ifaceNames);
}
} // namespace

using namespace testing::ext;
class NetStatsServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    uint32_t GetTestTime();
    static inline sptr<NetStatsCallbackTest> callback_ = nullptr;
};

void NetStatsServiceTest::SetUpTestCase()
{
    callback_ = new (std::nothrow) NetStatsCallbackTest();
    DelayedSingleton<NetStatsService>::GetInstance()->OnStart();
}

void NetStatsServiceTest::TearDownTestCase()
{
    DelayedSingleton<NetStatsService>::GetInstance()->OnStop();
}

void NetStatsServiceTest::SetUp() {}

void NetStatsServiceTest::TearDown() {}

/**
 * @tc.name: DumpTest001
 * @tc.desc: Test NetStatsService RegisterNetStatsCallback.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, DumpTest001, TestSize.Level1)
{
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->Dump(TEST_FD, {});
    EXPECT_GE(ret, -1);
}

/**
 * @tc.name: RegisterNetStatsCallbackTest001
 * @tc.desc: Test NetStatsService RegisterNetStatsCallback.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, RegisterNetStatsCallbackTest001, TestSize.Level1)
{
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->RegisterNetStatsCallback(callback_);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: RegisterNetStatsCallbackTest002
 * @tc.desc: Test NetStatsService RegisterNetStatsCallback.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, RegisterNetStatsCallbackTest002, TestSize.Level1)
{
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->RegisterNetStatsCallback(nullptr);
    EXPECT_NE(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: UnregisterNetStatsCallbackTest001
 * @tc.desc: Test NetStatsService UnregisterNetStatsCallback.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, UnregisterNetStatsCallbackTest001, TestSize.Level1)
{
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->UnregisterNetStatsCallback(callback_);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: UnregisterNetStatsCallbackTest002
 * @tc.desc: Test NetStatsService UnregisterNetStatsCallback.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, UnregisterNetStatsCallbackTest002, TestSize.Level1)
{
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->UnregisterNetStatsCallback(nullptr);
    EXPECT_NE(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: GetIfaceRxBytesTest001
 * @tc.desc: Test NetStatsService GetIfaceRxBytes.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, GetIfaceRxBytesTest001, TestSize.Level1)
{
    uint64_t stats = 0;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetIfaceRxBytes(stats, ETH_IFACE_NAME);
    EXPECT_GE(stats, static_cast<uint64_t>(0));
    DTEST_LOG << "Ret" << ret << std::endl;
}

/**
 * @tc.name: GetIfaceTxBytesTest001
 * @tc.desc: Test NetStatsService GetIfaceTxBytes.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, GetIfaceTxBytesTest001, TestSize.Level1)
{
    uint64_t stats = 0;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetIfaceTxBytes(stats, ETH_IFACE_NAME);
    EXPECT_GE(stats, static_cast<uint64_t>(0));
    DTEST_LOG << "Ret" << ret << std::endl;
}

/**
 * @tc.name: GetCellularRxBytesTest001
 * @tc.desc: Test NetStatsService GetCellularRxBytes.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, GetCellularRxBytesTest001, TestSize.Level1)
{
    std::list<std::string> ifaceNames;
    uint64_t stats = 0;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetCellularRxBytes(stats);
    GetIfaceNamesFromManager(ifaceNames);
    if (ifaceNames.empty()) {
        EXPECT_GE(ret, -1);
        return;
    }
    EXPECT_GE(stats, static_cast<uint64_t>(0));
}

/**
 * @tc.name: GetCellularTxBytesTest001
 * @tc.desc: Test NetStatsService GetCellularTxBytes.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, GetCellularTxBytesTest001, TestSize.Level1)
{
    std::list<std::string> ifaceNames;
    uint64_t stats = 0;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetCellularTxBytes(stats);
    GetIfaceNamesFromManager(ifaceNames);
    if (ifaceNames.empty()) {
        EXPECT_GE(ret, -1);
        return;
    }
    EXPECT_GE(stats, static_cast<uint64_t>(0));
}

/**
 * @tc.name: GetAllRxBytesTest001
 * @tc.desc: Test NetStatsService GetAllRxBytes.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, GetAllRxBytesTest001, TestSize.Level1)
{
    uint64_t stats = 0;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetAllRxBytes(stats);
    EXPECT_GE(stats, static_cast<uint64_t>(0));
    DTEST_LOG << "Ret" << ret << std::endl;
}

/**
 * @tc.name: GetAllTxBytesTest001
 * @tc.desc: Test NetStatsService GetAllTxBytes.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, GetAllTxBytesTest001, TestSize.Level1)
{
    uint64_t stats = 0;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetAllTxBytes(stats);
    EXPECT_GE(stats, static_cast<uint64_t>(0));
    DTEST_LOG << "Ret" << ret << std::endl;
}

/**
 * @tc.name: GetUidRxBytesTest001
 * @tc.desc: Test NetStatsService GetUidRxBytes.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, GetUidRxBytesTest001, TestSize.Level1)
{
    uint64_t stats = 0;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetUidRxBytes(stats, TEST_UID);
    EXPECT_GE(stats, static_cast<uint64_t>(0));
    DTEST_LOG << "Ret" << ret << std::endl;
}

/**
 * @tc.name: GetUidTxBytesTest001
 * @tc.desc: Test NetStatsService GetUidTxBytes.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, GetUidTxBytesTest001, TestSize.Level1)
{
    uint64_t stats = 0;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetUidTxBytes(stats, TEST_UID);
    EXPECT_GE(stats, static_cast<uint64_t>(0));
    DTEST_LOG << "Ret" << ret << std::endl;
}

/**
 * @tc.name: GetIfaceStatsDetail001
 * @tc.desc: Test NetStatsService GetIfaceStatsDetail.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, GetIfaceStatsDetail001, TestSize.Level1)
{
    NetStatsInfo info;
    std::string iface = "wlan0";
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetIfaceStatsDetail(iface, 0, UINT32_MAX, info);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: GetUidStatsDetail001
 * @tc.desc: Test NetStatsService GetUidStatsDetail.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, GetUidStatsDetail001, TestSize.Level1)
{
    NetStatsInfo info;
    std::string iface = "wlan0";
    uint32_t uid = 1234;
    int32_t ret =
        DelayedSingleton<NetStatsService>::GetInstance()->GetUidStatsDetail(iface, uid, 0, UINT32_MAX, info);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, GetUidStatsDetail002, TestSize.Level1)
{
    NetStatsInfo info;
    std::string iface = "wlan0";
    uint32_t uid = 2132132;
    int32_t ret =
        DelayedSingleton<NetStatsService>::GetInstance()->GetUidStatsDetail(iface, uid, 0, UINT32_MAX, info);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}
/**
 * @tc.name: UpdateIfacesStats
 * @tc.desc: Test NetStatsService UpdateIfacesStats.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, UpdateIfacesStats, TestSize.Level1)
{
    NetStatsInfo info;
    std::string iface = "wlan0";
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->UpdateIfacesStats(iface, 0, UINT32_MAX, info);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: ResetFactory001
 * @tc.desc: Test NetStatsService ResetFactory.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, ResetFactory001, TestSize.Level1)
{
    NetStatsInfo info;
    info.iface_ = "wlan0";
    info.date_ = 115200;
    info.rxBytes_ = 10000;
    info.txBytes_ = 11000;
    info.rxPackets_ = 1000;
    info.txPackets_ = 1100;

    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->ResetFactory();
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

/**
 * @tc.name: UpdateStatsData001
 * @tc.desc: Test NetStatsService UpdateStatsData.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, UpdateStatsData001, TestSize.Level1)
{
    NetStatsInfo info;
    info.iface_ = "wlan0";
    info.date_ = 115200;
    info.rxBytes_ = 10000;
    info.txBytes_ = 11000;
    info.rxPackets_ = 1000;
    info.txPackets_ = 1100;

    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->UpdateStatsData();
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, UpdateStatsDataInner001, TestSize.Level1)
{
    NetStatsInfo info;
    info.iface_ = "wlan1";
    info.date_ = 115200;
    info.rxBytes_ = 10000;
    info.txBytes_ = 11000;
    info.rxPackets_ = 1000;
    info.txPackets_ = 1100;

    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->UpdateStatsDataInner();
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, GetCookieRxBytesTest001, TestSize.Level1)
{
    uint64_t stats = 0;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetCookieRxBytes(stats, TEST_COOKIE);
    EXPECT_EQ(ret, NetManagerStandard::NETMANAGER_ERR_INTERNAL);
}

HWTEST_F(NetStatsServiceTest, GetCookieTxBytesTest001, TestSize.Level1)
{
    uint64_t stats = 0;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetCookieTxBytes(stats, TEST_COOKIE);
    EXPECT_EQ(ret, NetManagerStandard::NETMANAGER_ERR_INTERNAL);
}

HWTEST_F(NetStatsServiceTest, GetAllSimStatsInfoTest001, TestSize.Level1)
{
    std::vector<NetStatsInfo> infos;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetAllSimStatsInfo(infos);
    EXPECT_EQ(ret, NetManagerStandard::NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, GetTrafficStatsByNetworkTest001, TestSize.Level1)
{
    std::unordered_map<uint32_t, NetStatsInfo> infos;
    sptr<NetStatsNetwork> network = new (std::nothrow) NetStatsNetwork();
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetTrafficStatsByNetwork(infos, *network);
    EXPECT_EQ(ret, NetManagerStandard::NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, GetTrafficStatsByUidNetworkTest001, TestSize.Level1)
{
    std::vector<NetStatsInfoSequence> infos;
    uint32_t uid = 1;
    sptr<NetStatsNetwork> network = new (std::nothrow) NetStatsNetwork();
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->GetTrafficStatsByUidNetwork(infos, uid, *network);
    EXPECT_EQ(ret, NetManagerStandard::NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, SetAppStats001, TestSize.Level1)
{
    PushStatsInfo info;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->SetAppStats(info);
    EXPECT_EQ(ret, NetManagerStandard::NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, OnStartTest001, TestSize.Level1)
{
    DelayedSingleton<NetStatsService>::GetInstance()->state_ =
        DelayedSingleton<NetStatsService>::GetInstance()->STATE_RUNNING;
    DelayedSingleton<NetStatsService>::GetInstance()->OnStart();
    EXPECT_EQ(DelayedSingleton<NetStatsService>::GetInstance()->state_, 1);
}

HWTEST_F(NetStatsServiceTest, GetIfaceStatsDetailTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    const std::string iface = "wlan0";
    uint64_t start = 1;
    uint64_t end = 0;
    NetStatsInfo statsInfo{};
    int32_t ret = netStatsService->GetIfaceStatsDetail(iface, start, end, statsInfo);
    EXPECT_EQ(ret, NETMANAGER_ERR_INVALID_PARAMETER);

    end = 2; // end 2
    netStatsService->netStatsCached_ = nullptr;
    ret = netStatsService->GetIfaceStatsDetail(iface, start, end, statsInfo);
    EXPECT_EQ(ret, NETMANAGER_ERR_LOCAL_PTR_NULL);

    netStatsService->netStatsCached_ = std::make_unique<NetStatsCached>();
    ret = netStatsService->GetIfaceStatsDetail(iface, start, end, statsInfo);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, GetUidStatsDetailTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    const std::string iface = "wlan0";
    uint32_t uid = 1;
    uint64_t start = 1;
    uint64_t end = 0;
    NetStatsInfo statsInfo{};
    int32_t ret = netStatsService->GetUidStatsDetail(iface, uid, start, end, statsInfo);
    EXPECT_EQ(ret, NETMANAGER_ERR_INVALID_PARAMETER);

    end = 2; // end 2
    netStatsService->netStatsCached_ = nullptr;
    ret = netStatsService->GetUidStatsDetail(iface, uid, start, end, statsInfo);
    EXPECT_EQ(ret, NETMANAGER_ERR_LOCAL_PTR_NULL);

    netStatsService->netStatsCached_ = std::make_unique<NetStatsCached>();
    ret = netStatsService->GetUidStatsDetail(iface, uid, start, end, statsInfo);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, UpdateIfacesStatsTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    const std::string iface = "wlan0";
    uint64_t start = 1;
    uint64_t end = 0;
    NetStatsInfo statsInfo{};
    int32_t ret = netStatsService->UpdateIfacesStats(iface, start, end, statsInfo);
    EXPECT_EQ(ret, NETMANAGER_ERR_INVALID_PARAMETER);

    end = 2; // end 2
    ret = netStatsService->UpdateIfacesStats(iface, start, end, statsInfo);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, UpdateStatsDataTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    netStatsService->netStatsCached_ = nullptr;
    int32_t ret = netStatsService->UpdateStatsData();
    EXPECT_EQ(ret, NETMANAGER_ERR_LOCAL_PTR_NULL);
    int32_t ret2 = netStatsService->UpdateStatsDataInner();
    EXPECT_EQ(ret, NETMANAGER_ERR_LOCAL_PTR_NULL);
}

HWTEST_F(NetStatsServiceTest, GetAllStatsInfoTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    NetStatsInfo netStatsInfo;
    std::vector<NetStatsInfo> infos = {netStatsInfo};
    netStatsService->netStatsCached_ = nullptr;
    int32_t ret = netStatsService->GetAllStatsInfo(infos);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    netStatsService->netStatsCached_ = std::make_unique<NetStatsCached>();
    ret = netStatsService->GetAllStatsInfo(infos);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, GetTrafficStatsByNetworkTest002, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    NetStatsInfo netStatsInfo;
    std::unordered_map<uint32_t, NetStatsInfo> infos = {{1, netStatsInfo}};
    const sptr<NetStatsNetwork> network1 = nullptr;
    netStatsService->netStatsCached_ = nullptr;
    int32_t ret = netStatsService->GetTrafficStatsByNetwork(infos, *network1);
    EXPECT_EQ(ret, NETMANAGER_ERR_LOCAL_PTR_NULL);

    netStatsService->netStatsCached_ = std::make_unique<NetStatsCached>();
    ret = netStatsService->GetTrafficStatsByNetwork(infos, *network1);
    EXPECT_EQ(ret, NETMANAGER_ERR_LOCAL_PTR_NULL);

    const sptr<NetStatsNetwork> network2 = new (std::nothrow) NetStatsNetwork();
    ret = netStatsService->GetTrafficStatsByNetwork(infos, *network2);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    network2->type_ = 1;
    ret = netStatsService->GetTrafficStatsByNetwork(infos, *network2);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, GetTrafficStatsByNetworkTest003, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    NetStatsInfo netStatsInfo;
    std::unordered_map<uint32_t, NetStatsInfo> infos = {{1, netStatsInfo}};
    uint32_t uid = 1;
    netStatsService->netStatsCached_ = std::make_unique<NetStatsCached>();
    const sptr<NetStatsNetwork> network = new (std::nothrow) NetStatsNetwork();
    network->type_ = 0;
    network->startTime_ = 1;
    network->endTime_ = 1;
    PushStatsInfo info{};
    info.uid_ = 1;
    info.iface_ = "rmnet_push";
    info.simId_ = 1;
    info.netBearType_ = 1;
    info.rxBytes_ = 1;
    info.txBytes_ = 1;
    netStatsService->netStatsCached_->SetAppStats(info);
    int32_t ret = netStatsService->GetTrafficStatsByNetwork(infos, *network);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    network->simId_ = info.simId_;
    ret = netStatsService->GetTrafficStatsByNetwork(infos, *network);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    network->startTime_ = info.beginTime_;
    ret = netStatsService->GetTrafficStatsByNetwork(infos, *network);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    network->endTime_ = info.endTime_;
    ret = netStatsService->GetTrafficStatsByNetwork(infos, *network);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, GetTrafficStatsByUidNetworkTest002, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    std::vector<NetStatsInfoSequence> infos = {};
    uint32_t uid = 1;
    const sptr<NetStatsNetwork> network1 = nullptr;
    netStatsService->netStatsCached_ = nullptr;
    int32_t ret = netStatsService->GetTrafficStatsByUidNetwork(infos, uid, *network1);
    EXPECT_EQ(ret, NETMANAGER_ERR_LOCAL_PTR_NULL);

    netStatsService->netStatsCached_ = std::make_unique<NetStatsCached>();
    ret = netStatsService->GetTrafficStatsByUidNetwork(infos, uid, *network1);
    EXPECT_EQ(ret, NETMANAGER_ERR_LOCAL_PTR_NULL);

    const sptr<NetStatsNetwork> network2 = new (std::nothrow) NetStatsNetwork();
    ret = netStatsService->GetTrafficStatsByUidNetwork(infos, uid, *network2);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    network2->type_ = 1;
    ret = netStatsService->GetTrafficStatsByUidNetwork(infos, uid, *network2);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, GetTrafficStatsByUidNetworkTest003, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    std::vector<NetStatsInfoSequence> infos = {};
    uint32_t uid = 1;
    netStatsService->netStatsCached_ = std::make_unique<NetStatsCached>();
    const sptr<NetStatsNetwork> network = new (std::nothrow) NetStatsNetwork();
    network->type_ = 0;
    network->startTime_ = 1;
    network->endTime_ = 1;
    PushStatsInfo info{};
    info.uid_ = 101; // 101
    info.iface_ = "rmnet_push";
    info.simId_ = 1;
    info.netBearType_ = 1;
    info.rxBytes_ = 1;
    info.txBytes_ = 1;
    netStatsService->netStatsCached_->SetAppStats(info);
    int32_t ret = netStatsService->GetTrafficStatsByUidNetwork(infos, uid, *network);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    uid = info.uid_;
    ret = netStatsService->GetTrafficStatsByUidNetwork(infos, uid, *network);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    network->simId_ = info.simId_;
    ret = netStatsService->GetTrafficStatsByUidNetwork(infos, uid, *network);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    network->startTime_ = info.beginTime_;
    ret = netStatsService->GetTrafficStatsByUidNetwork(infos, uid, *network);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    network->endTime_ = info.endTime_;
    ret = netStatsService->GetTrafficStatsByUidNetwork(infos, uid, *network);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, GetTrafficStatsByUidNetworkTest004, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    std::vector<NetStatsInfoSequence> infos = {};
    uint32_t uid = 1;
    netStatsService->netStatsCached_ = std::make_unique<NetStatsCached>();
    const sptr<NetStatsNetwork> network2 = new (std::nothrow) NetStatsNetwork();
    network2->type_ = 1;
    netStatsService->netStatsCached_->CacheUidStats();
    int32_t ret = netStatsService->GetTrafficStatsByUidNetwork(infos, uid, *network2);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, SetAppStatsTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    const PushStatsInfo info{};
    netStatsService->netStatsCached_ = nullptr;
    int32_t ret = netStatsService->SetAppStats(info);
    EXPECT_EQ(ret, NETMANAGER_ERR_LOCAL_PTR_NULL);
}

/**
 * @tc.name: StartSysTimerTest001
 * @tc.desc: Test NetStatsService StartSysTimer.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, StartSysTimerTest001, TestSize.Level1)
{
    DelayedSingleton<NetStatsService>::GetInstance()->netStatsSysTimerId_ = 100;
    DelayedSingleton<NetStatsService>::GetInstance()->StartSysTimer();
    EXPECT_EQ(DelayedSingleton<NetStatsService>::GetInstance()->netStatsSysTimerId_, 100);
    DelayedSingleton<NetStatsService>::GetInstance()->netStatsSysTimerId_ = 0;
    DelayedSingleton<NetStatsService>::GetInstance()->StartSysTimer();
    EXPECT_EQ(DelayedSingleton<NetStatsService>::GetInstance()->netStatsSysTimerId_, 0);
}

/**
 * @tc.name: StopSysTimerTest001
 * @tc.desc: Test NetStatsService StopSysTimer.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, StopSysTimerTest001, TestSize.Level1)
{
    DelayedSingleton<NetStatsService>::GetInstance()->netStatsSysTimerId_ = 0;
    DelayedSingleton<NetStatsService>::GetInstance()->StopSysTimer();
    DelayedSingleton<NetStatsService>::GetInstance()->netStatsSysTimerId_ = 1000;
    DelayedSingleton<NetStatsService>::GetInstance()->StopSysTimer();
    EXPECT_EQ(DelayedSingleton<NetStatsService>::GetInstance()->netStatsSysTimerId_, 0);
}

/**
 * @tc.name: ModifySysTimerTest001
 * @tc.desc: Test NetStatsService StopSysTimer.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsServiceTest, ModifySysTimerTest001, TestSize.Level1)
{
    DelayedSingleton<NetStatsService>::GetInstance()->netStatsSysTimerId_ = 0;
    int32_t ret = DelayedSingleton<NetStatsService>::GetInstance()->ModifySysTimer();
    EXPECT_EQ(ret, NETMANAGER_ERROR);
    DelayedSingleton<NetStatsService>::GetInstance()->netStatsSysTimerId_ = 1000;
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsServiceTest, OnAddSystemAbilityTest001, TestSize.Level1)
{
    DelayedSingleton<NetStatsService>::GetInstance()->OnAddSystemAbility(TIME_SERVICE_ID, "10");
    EXPECT_NE(DelayedSingleton<NetStatsService>::GetInstance()->netStatsSysTimerId_, 0);
}

HWTEST_F(NetStatsServiceTest, InitPrivateUserIdTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    netStatsService->InitPrivateUserId();
    int32_t userId = netStatsService->netStatsCached_->GetCurPrivateUserId();
    EXPECT_EQ(userId, 100);
}

HWTEST_F(NetStatsServiceTest, ProcessOsAccountChangedTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    AccountSA::OsAccountState state = AccountSA::OsAccountState::CREATED;
    int32_t userId = 101;
    int32_t ret = netStatsService->ProcessOsAccountChanged(userId, state);
    EXPECT_EQ(ret, 0);
    state = AccountSA::OsAccountState::STOPPING;
    ret = netStatsService->ProcessOsAccountChanged(888, state);
    EXPECT_EQ(ret, 0);
    netStatsService->netStatsCached_->SetCurPrivateUserId(101);
    EXPECT_EQ(netStatsService->netStatsCached_->GetCurPrivateUserId(), 101);
    netStatsService->netStatsCached_->SetCurPrivateUserId(101);
    EXPECT_EQ(netStatsService->netStatsCached_->GetCurPrivateUserId(), -1);
    state = AccountSA::OsAccountState::INVALID_TYPE;
    ret = netStatsService->ProcessOsAccountChanged(888, state);
}

HWTEST_F(NetStatsServiceTest, MergeTrafficStatsByAccountTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    
    int32_t curUserId = -1;
    int32_t ret1 = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(curUserId);
    int32_t defaultUserId = -1;
    int32_t ret2 = AccountSA::OsAccountManager::GetDefaultActivatedOsAccount(defaultUserId);
    if (ret1 != 0 || ret2 != 0) {
        return;
    }

    std::vector<NetStatsInfo> infos;
    NetStatsInfo info1;
    info1.userId_ = curUserId;
    NetStatsInfo info2;
    info2.userId_ = 101;
    infos.push_back(info1);
    infos.push_back(info2);
    netStatsService->netStatsCached_->SetCurPrivateUserId(101);

    if (curUserId == defaultUserId) {
        netStatsService->MergeTrafficStatsByAccount(infos);
        EXPECT_EQ(infos[1].userId_, OTHER_ACCOUNT_UID);
    }
}

HWTEST_F(NetStatsServiceTest, GetHistoryDataTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    std::vector<NetStatsInfo> infos;
    uint32_t start = 1745847234;
    uint32_t end = 1745847823;
    netStatsService->GetHistoryData(infos, "111", 12345612, 0, UINT32_MAX);
    EXPECT_EQ(infos.size(), 0);
    netStatsService->GetHistoryData(infos, "111", DEFAULT_ACCOUNT_UID, 0, UINT32_MAX);
    netStatsService->netStatsCached_->SetCurPrivateUserId(101);

    int32_t ret = netStatsService->GetHistoryData(infos, "111", OTHER_ACCOUNT_UID, 0, UINT32_MAX);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
    netStatsService->netStatsCached_->SetCurPrivateUserId(-1);
    ret = netStatsService->GetHistoryData(infos, "111", OTHER_ACCOUNT_UID, 0, UINT32_MAX);
    EXPECT_EQ(ret, NETMANAGER_ERROR);
}

HWTEST_F(NetStatsServiceTest, DeleteTrafficStatsByAccountTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    int32_t defaultUserId = -1;
    AccountSA::OsAccountManager::GetDefaultActivatedOsAccount(defaultUserId);
    std::vector<NetStatsInfoSequence> infos;
    NetStatsInfoSequence info1;
    info1.info_.userId_ = defaultUserId;
    NetStatsInfoSequence info2;
    info2.info_.userId_ = defaultUserId + 1;
    NetStatsInfoSequence info3;
    info3.info_.userId_ = 12345612;
    NetStatsInfoSequence info4;
    info3.info_.userId_ = 0;
    infos.push_back(info1);
    infos.push_back(info2);
    infos.push_back(info3);
    infos.push_back(info4);
    netStatsService->DeleteTrafficStatsByAccount(infos, DEFAULT_ACCOUNT_UID);
    EXPECT_EQ(infos.size(), 2);
    infos.push_back(info1);
    infos.push_back(info2);
    infos.push_back(info3);
    infos.push_back(info4);
    netStatsService->DeleteTrafficStatsByAccount(infos, OTHER_ACCOUNT_UID);
    EXPECT_EQ(infos.size(), 2);
    infos.push_back(info1);
    infos.push_back(info2);
    infos.push_back(info3);
    infos.push_back(info4);
    netStatsService->DeleteTrafficStatsByAccount(infos, 888);
    EXPECT_EQ(infos.size(), 4);
}

HWTEST_F(NetStatsServiceTest, CalculateTrafficAvailableTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    int32_t simId = 1;
    bool ret = netStatsService->CalculateTrafficAvailable(simId, UINT64_MAX, UINT64_MAX, UINT64_MAX);
    EXPECT_EQ(ret, false);

    netStatsService->settingsTrafficMap_.insert(
                std::make_pair(simId, std::make_pair(trafficDataObserver, trafficSettingsInfo)));
    netStatsService->CalculateTrafficAvailable(simId, UINT64_MAX, UINT64_MAX, UINT64_MAX);
    EXPECT_EQ(ret, true);
}

#ifdef SUPPORT_TRAFFIC_STATISTIC
HWTEST_F(NetStatsServiceTest, UpdateBpfMapTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    int32_t simId = 1;
    netStatsService->settingsTrafficMap_.insert(
                std::make_pair(simId, std::make_pair(trafficDataObserver, trafficSettingsInfo)));
    netStatsService->UpdateBpfMap(simId);
    EXPECT_EQ(ret, true);
}

HWTEST_F(NetStatsServiceTest, UpdateBpfMapTimerTest001, TestSize.Level1)
{
    auto netStatsService1 = DelayedSingleton<NetStatsService>::GetInstance();
    netStatsService1->trafficPlanFfrtQueue_ = nullptr;
    netStatsService1->UpdateBpfMapTimer();

    auto netStatsService2 = DelayedSingleton<NetStatsService>::GetInstance();
    netStatsService2->trafficPlanFfrtQueue_ = nullptr;
    netStatsService2->UpdateBpfMapTimer();
    EXPECT_EQ(netStatsService2->settingsTrafficMap_.size(), 0);
}

HWTEST_F(NetStatsServiceTest, CellularDataStateChangedFfrtTest001, TestSize.Level1)
{
    auto netStatsService1 = DelayedSingleton<NetStatsService>::GetInstance();
    netStatsService1->CellularDataStateChangedFfrt(0,
        static_cast<int32_t>(Telephony::DataConnectState::DATA_STATE_CONNECTED));
    netStatsService1->CellularDataStateChangedFfrt(0,
        static_cast<int32_t>(Telephony::DataConnectState::DATA_STATE_CONNECTING));

    netStatsService1->simIdToIfIndexMap_.insert(1, 12);
    netStatsService1->CellularDataStateChangedFfrt(0,
        static_cast<int32_t>(Telephony::DataConnectState::DATA_STATE_CONNECTED));
    auto ret = netStatsService1->CellularDataStateChangedFfrt(0,
        static_cast<int32_t>(Telephony::DataConnectState::DATA_STATE_CONNECTING));
    EXPECT_EQ(simIdToIfIndexMap_.find(1), nullptr);
    EXPECT_EQ(ret, true);
}

HWTEST_F(NetStatsServiceTest, UpdateCurActiviteSimChangedTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    int32_t slotId = Telephony::CoreServiceClient::GetInstance().GetSlotId(simId);
    int32_t simId = Telephony::CoreServiceClient::GetInstance().GetSimId(slotId);
    netStatsService->settingsTrafficMap_.insert(
        std::make_pair(simId, std::make_pair(trafficDataObserver, trafficSettingsInfo)));
    netStatsService->UpdateCurActiviteSimChanged(simId, 12);
    EXPECT_EQ(ret, true);
}

HWTEST_F(NetStatsServiceTest, AddSimIdInTwoMapTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    int32_t slotId = Telephony::CoreServiceClient::GetInstance().GetSlotId(simId);
    int32_t simId = Telephony::CoreServiceClient::GetInstance().GetSimId(slotId);
    netStatsService->settingsTrafficMap_.insert(
        std::make_pair(simId, std::make_pair(trafficDataObserver, trafficSettingsInfo)));
    netStatsService->AddSimIdInTwoMap(simId, 12);
    EXPECT_EQ(ret, true);
}

HWTEST_F(NetStatsServiceTest, SetTrafficMapMaxValueTest001, TestSize.Level1)
{
    auto netStatsService = DelayedSingleton<NetStatsService>::GetInstance();
    netStatsService->SetTrafficMapMaxValue(0);
    netStatsService->SetTrafficMapMaxValue(1);
    netStatsService->SetTrafficMapMaxValue(2);
    EXPECT_NE(netStatsService, nullptr);
}
#endif
} // namespace NetManagerStandard
} // namespace OHOS

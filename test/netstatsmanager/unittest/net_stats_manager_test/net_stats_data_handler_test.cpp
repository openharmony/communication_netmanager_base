/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <memory>
#include <random>

#include <gtest/gtest.h>

#ifdef GTEST_API_
#define private public
#endif
#include "net_mgr_log_wrapper.h"
#include "net_stats_constants.h"
#include "net_stats_data_handler.h"
#include "net_stats_database_defines.h"
#include "net_stats_database_helper.h"

namespace OHOS {
namespace NetManagerStandard {
using namespace NetStatsDatabaseDefines;

using namespace testing::ext;
namespace {
constexpr uint32_t UID_MAX_TEST = 200;
constexpr uint32_t MAX_TEST_DATA = 100;
constexpr uint32_t UID = 2000222;
const std::vector<std::string> MOCK_IFACE = {"wlan0", "eth0", "eth1", "usb0", "wlan1", "usb1"};
std::random_device g_rd;
std::mt19937 g_regn(g_rd());
uint32_t GetUint32()
{
    return static_cast<uint32_t>(g_regn()) % UID_MAX_TEST;
}

uint32_t GetIndet()
{
    return static_cast<uint32_t>(g_regn()) % 3;  // 3: eg. ident 0-2
}

uint64_t GetUint64()
{
    return static_cast<uint64_t>(g_regn());
}

std::string GetMockIface()
{
    return MOCK_IFACE.at(g_regn() % MOCK_IFACE.size());
}
std::vector<NetStatsInfo> g_statsData;

NetStatsInfo CreateMockStatsInfo()
{
    NetStatsInfo info;
    info.uid_ = GetUint32();
    info.ident_ = std::to_string(GetIndet());
    info.date_ = GetUint64();
    info.iface_ = GetMockIface();
    info.rxBytes_ = GetUint64();
    info.rxPackets_ = GetUint64();
    info.txBytes_ = GetUint64();
    info.txPackets_ = GetUint64();
    return info;
}

void CreateMockStatsData()
{
    g_statsData.clear();
    for (uint32_t i = 0; i < MAX_TEST_DATA - 3; i++) {  // 3： add other info
        NetStatsInfo info;
        info.uid_ = GetUint32();
        info.ident_ = std::to_string(GetIndet());
        info.date_ = GetUint64();
        info.iface_ = GetMockIface();
        info.rxBytes_ = GetUint64();
        info.rxPackets_ = GetUint64();
        info.txBytes_ = GetUint64();
        info.txPackets_ = GetUint64();
        g_statsData.push_back(info);
    }
    NetStatsInfo info1;
    info1.uid_ = GetUint32();
    info1.ident_ = std::to_string(1);
    info1.date_ = GetUint64();
    info1.iface_ = GetMockIface();
    info1.rxBytes_ = GetUint64();
    info1.rxPackets_ = GetUint64();
    info1.txBytes_ = GetUint64();
    info1.txPackets_ = GetUint64();
    info1.flag_ = STATS_DATA_FLAG_SIM2;
    g_statsData.push_back(info1);
    NetStatsInfo info2;
    info2.uid_ = GetUint32();
    info2.ident_ = std::to_string(2);  // ident:2
    info2.date_ = GetUint64();
    info2.iface_ = GetMockIface();
    info2.rxBytes_ = GetUint64();
    info2.rxPackets_ = GetUint64();
    info2.txBytes_ = GetUint64();
    info2.txPackets_ = GetUint64();
    info2.flag_ = STATS_DATA_FLAG_SIM;
    g_statsData.push_back(info2);
    NetStatsInfo info0;
    info0.uid_ = GetUint32();
    info0.ident_ = std::to_string(0);
    info0.date_ = GetUint64();
    info0.iface_ = GetMockIface();
    info0.rxBytes_ = GetUint64();
    info0.rxPackets_ = GetUint64();
    info0.txBytes_ = GetUint64();
    info0.txPackets_ = GetUint64();
    info0.flag_ = STATS_DATA_FLAG_SIM2_BASIC;
    g_statsData.push_back(info0);
}

void ClearMockStatsData()
{
    g_statsData.clear();
}
} // namespace

class NetStatsDataHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NetStatsDataHandlerTest::SetUpTestCase()
{
    CreateMockStatsData();
}

void NetStatsDataHandlerTest::TearDownTestCase()
{
    ClearMockStatsData();
}

void NetStatsDataHandlerTest::SetUp() {}

void NetStatsDataHandlerTest::TearDown() {}

HWTEST_F(NetStatsDataHandlerTest, WriteStatsDataTest001, TestSize.Level1)
{
    NetStatsDataHandler handler;
    CreateMockStatsData();
    int32_t ret = handler.WriteStatsData(g_statsData, UID_TABLE);
    ClearMockStatsData();
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, WriteStatsDataTest002, TestSize.Level1)
{
    NetStatsDataHandler handler;
    std::vector<NetStatsInfo> mockEmptyStatsData;
    int32_t ret = handler.WriteStatsData(mockEmptyStatsData, UID_TABLE);
    EXPECT_EQ(ret, NETMANAGER_ERR_PARAMETER_ERROR);
}

HWTEST_F(NetStatsDataHandlerTest, WriteStatsDataTest003, TestSize.Level1)
{
    NetStatsDataHandler handler;
    std::vector<NetStatsInfo> mockStatsData;
    mockStatsData.push_back(CreateMockStatsInfo());
    std::string mockEmptyIfaceName;
    int32_t ret = handler.WriteStatsData(mockStatsData, mockEmptyIfaceName);
    EXPECT_EQ(ret, NETMANAGER_ERR_PARAMETER_ERROR);
}

HWTEST_F(NetStatsDataHandlerTest, WriteStatsDataTest004, TestSize.Level1)
{
    NetStatsDataHandler handler;
    CreateMockStatsData();
    int32_t ret = handler.WriteStatsData(g_statsData, IFACE_TABLE);
    ClearMockStatsData();
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, WriteStatsDataTest005, TestSize.Level1)
{
    NetStatsDataHandler handler;
    CreateMockStatsData();
    int32_t ret = handler.WriteStatsData(g_statsData, UID_SIM_TABLE);
    ClearMockStatsData();
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, ReadStatsDataTest001, TestSize.Level1)
{
    NETMGR_LOG_E("NetStatsDataHandlerTest ReadStatsDataTest001 enter");
    NetStatsDataHandler handler;
    std::vector<NetStatsInfo> infos;
    int32_t ret = handler.ReadStatsData(infos, 0, LONG_MAX);
    std::cout << "Data size: " << infos.size() << std::endl;
    std::for_each(infos.begin(), infos.end(), [](const auto &info) { std::cout << info.UidData() << std::endl; });
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, ReadStatsDataTest002, TestSize.Level1)
{
    NetStatsDataHandler handler;
    std::vector<NetStatsInfo> infos;
    std::string iface;
    int32_t ret = handler.ReadStatsData(infos, iface, 0, LONG_MAX);
    std::cout << "Data size: " << infos.size() << std::endl;
    std::for_each(infos.begin(), infos.end(), [](const auto &info) { std::cout << info.UidData() << std::endl; });
    EXPECT_EQ(ret, NETMANAGER_ERR_PARAMETER_ERROR);
}

HWTEST_F(NetStatsDataHandlerTest, ReadStatsDataTest003, TestSize.Level1)
{
    NetStatsDataHandler handler;
    std::vector<NetStatsInfo> infos;
    std::string iface = "testIface";
    int32_t ret = handler.ReadStatsData(infos, iface, 0, LONG_MAX);
    std::cout << "Data size: " << infos.size() << std::endl;
    std::for_each(infos.begin(), infos.end(), [](const auto &info) { std::cout << info.UidData() << std::endl; });
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, ReadStatsDataTest004, TestSize.Level1)
{
    NetStatsDataHandler handler;
    std::vector<NetStatsInfo> infos;
    uint32_t testUid = 122;
    std::string emptyIface = "";
    int32_t ret = handler.ReadStatsData(infos, emptyIface, testUid, 0, LONG_MAX);
    std::cout << "Data size: " << infos.size() << std::endl;
    std::for_each(infos.begin(), infos.end(), [](const auto &info) { std::cout << info.UidData() << std::endl; });
    EXPECT_EQ(ret, NETMANAGER_ERR_PARAMETER_ERROR);
}

HWTEST_F(NetStatsDataHandlerTest, ReadStatsDataTest005, TestSize.Level1)
{
    NetStatsDataHandler handler;
    std::vector<NetStatsInfo> infos;
    uint32_t testUid = 122;
    std::string iface = "testIface";
    int32_t ret = handler.ReadStatsData(infos, iface, 0, testUid, LONG_MAX);
    std::cout << "Data size: " << infos.size() << std::endl;
    std::for_each(infos.begin(), infos.end(), [](const auto &info) { std::cout << info.UidData() << std::endl; });
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, ReadStatsDataTest006, TestSize.Level1)
{
    NetStatsDataHandler handler;
    std::vector<NetStatsInfo> infos;
    std::string ident = "2";
    int32_t ret = handler.ReadStatsDataByIdent(infos, ident, 0, LONG_MAX);
    std::cout << "Data size: " << infos.size() << std::endl;
    std::for_each(infos.begin(), infos.end(), [](const auto &info) { std::cout << info.UidData() << std::endl; });
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, ReadStatsDataTest007, TestSize.Level1)
{
    NetStatsDataHandler handler;
    std::vector<NetStatsInfo> infos;
    uint32_t uid = UID;
    std::string ident = "2";
    int32_t ret = handler.ReadStatsData(infos, uid, ident, 0, LONG_MAX);
    std::cout << "Data size: " << infos.size() << std::endl;
    std::for_each(infos.begin(), infos.end(), [](const auto &info) { std::cout << info.UidData() << std::endl; });
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
    uid = SIM2_UID;
    ret = handler.ReadStatsData(infos, uid, ident, 0, LONG_MAX);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
    uid = Sim_UID;
    ret = handler.ReadStatsData(infos, uid, ident, 0, LONG_MAX);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, NetStatsDataHandlerBranchTest001, TestSize.Level1)
{
    NetStatsDataHandler handler;
    uint64_t uid = 100;
    int32_t ret = handler.DeleteByUid(uid);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);

    std::string tableName = "";
    ret = handler.DeleteByDate(tableName, 0, 0);
    EXPECT_NE(ret, NETMANAGER_SUCCESS);

    ret = handler.ClearData();
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, BackupNetStatsDataTest001, TestSize.Level1)
{
    NetStatsDataHandler handler;
    int ret = handler.BackupNetStatsData(NET_STATS_DATABASE_PATH, NET_STATS_DATABASE_BACK_PATH);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
    ret = handler.BackupNetStatsData("xxxx/xxxx.db", NET_STATS_DATABASE_BACK_PATH);
    EXPECT_NE(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, ReadStatsDataByIdentAndUserIdTest001, TestSize.Level1)
{
    NetStatsDataHandler handler;
    handler.isDisplayTrafficAncoList = false;
    std::vector<NetStatsInfo> infos;
    std::string ident = "0";
    int32_t userId = 100;
    uint64_t start = 1745894718;
    uint64_t end = 1745895733;
    int32_t ret = handler.ReadStatsDataByIdentAndUserId(infos, ident, userId, start, end);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
    handler.isDisplayTrafficAncoList = true;
    ret = handler.ReadStatsDataByIdentAndUserId(infos, ident, userId, start, end);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, UpdateStatsFlagByUserIdTest001, TestSize.Level1)
{
    NetStatsDataHandler handler;
    int32_t userId = 100;
    uint32_t flag = 0;
    int32_t ret = handler.UpdateStatsFlagByUserId(userId, flag);
    EXPECT_NE(ret, NETMANAGER_ERR_INTERNAL);
}

HWTEST_F(NetStatsDataHandlerTest, UpdateSimStatsFlagByUserIdTest001, TestSize.Level1)
{
    NetStatsDataHandler handler;
    int32_t userId = 100;
    uint32_t flag = 0;
    int32_t ret = handler.UpdateSimStatsFlagByUserId(userId, flag);
    EXPECT_NE(ret, NETMANAGER_ERR_INTERNAL);
}

HWTEST_F(NetStatsDataHandlerTest, UpdateStatsUserIdByUserIdTest001, TestSize.Level1)
{
    NetStatsDataHandler handler;
    int32_t userId = 100;
    int32_t newUserId = 0;
    int32_t ret = handler.UpdateStatsUserIdByUserId(userId, newUserId);
    EXPECT_NE(ret, NETMANAGER_ERR_INTERNAL);
}

HWTEST_F(NetStatsDataHandlerTest, DeleteSimStatsByUidTest001, TestSize.Level1)
{
    NetStatsDataHandler handler;
    uint64_t uid = 100;
    int32_t ret = handler.DeleteSimStatsByUid(uid);
    EXPECT_NE(ret, NETMANAGER_ERR_INTERNAL);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
    uint32_t flag = 100;
    ret = handler.UpdateStatsFlag(uid, flag);
    EXPECT_NE(ret, NETMANAGER_ERR_INTERNAL);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}

HWTEST_F(NetStatsDataHandlerTest, UpdateSimTest001, TestSize.Level1)
{
    NetStatsDataHandler handler;
    uint64_t uid = 100;
    uint32_t flag = 100;
    int32_t ret = handler.UpdateSimStatsFlag(uid, flag);
    EXPECT_NE(ret, NETMANAGER_ERR_INTERNAL);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
    ret = handler.UpdateSimDataFlag(uid, flag);
    EXPECT_NE(ret, NETMANAGER_ERR_INTERNAL);
    EXPECT_EQ(ret, NETMANAGER_SUCCESS);
}
} // namespace NetManagerStandard
} // namespace OHOS

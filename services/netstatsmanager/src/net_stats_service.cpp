/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "net_stats_service.h"

#include <dlfcn.h>
#include <net/if.h>
#include <sys/time.h>
#include <unistd.h>

#include <cinttypes>
#include <initializer_list>

#include "bpf_stats.h"
#include "broadcast_manager.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "ffrt_inner.h"
#include "net_bundle.h"
#include "net_manager_center.h"
#include "net_manager_constants.h"
#include "net_mgr_log_wrapper.h"
#include "net_stats_constants.h"
#include "net_stats_database_defines.h"
#include "net_stats_service_common.h"
#include "netmanager_base_common_utils.h"
#include "netmanager_base_permission.h"
#include "netmanager_hitrace.h"
#include "netsys_controller.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace NetManagerStandard {
using namespace NetStatsDatabaseDefines;
namespace {
constexpr std::initializer_list<NetBearType> BEAR_TYPE_LIST = {
    NetBearType::BEARER_CELLULAR, NetBearType::BEARER_WIFI, NetBearType::BEARER_BLUETOOTH,
    NetBearType::BEARER_ETHERNET, NetBearType::BEARER_VPN,  NetBearType::BEARER_WIFI_AWARE,
};
constexpr uint32_t DAY_SECONDS = 2 * 24 * 60 * 60;
constexpr const char* UID = "uid";
const std::string LIB_NET_BUNDLE_UTILS_PATH = "libnet_bundle_utils.z.so";
constexpr uint64_t DELAY_US = 35 * 1000 * 1000;
} // namespace
const bool REGISTER_LOCAL_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<NetStatsService>::GetInstance().get());

NetStatsService::NetStatsService()
    : SystemAbility(COMM_NET_STATS_MANAGER_SYS_ABILITY_ID, true), registerToService_(false), state_(STATE_STOPPED)
{
    netStatsCallback_ = std::make_shared<NetStatsCallback>();
    netStatsCached_ = std::make_unique<NetStatsCached>();
}

NetStatsService::~NetStatsService() = default;

void NetStatsService::OnStart()
{
    if (state_ == STATE_RUNNING) {
        NETMGR_LOG_D("the state is already running");
        return;
    }
    if (!Init()) {
        NETMGR_LOG_E("init failed");
        return;
    }
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    state_ = STATE_RUNNING;
    sptr<NetStatsBaseService> baseService = new (std::nothrow) NetStatsServiceCommon();
    if (baseService == nullptr) {
        NETMGR_LOG_E("Net stats base service instance create failed");
        return;
    }
    NetManagerCenter::GetInstance().RegisterStatsService(baseService);
}

void NetStatsService::OnStop()
{
    state_ = STATE_STOPPED;
    registerToService_ = true;
}

int32_t NetStatsService::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    NETMGR_LOG_D("Start Dump, fd: %{public}d", fd);
    std::string result;
    GetDumpMessage(result);
    int32_t ret = dprintf(fd, "%s\n", result.c_str());
    return ret < 0 ? STATS_DUMP_MESSAGE_FAIL : NETMANAGER_SUCCESS;
}

void NetStatsService::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId == BUNDLE_MGR_SERVICE_SYS_ABILITY_ID) {
        RefreshUidStatsFlag(DELAY_US);
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SHUTDOWN);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPriority(1);
    subscriber_ = std::make_shared<NetStatsListener>(subscribeInfo);
    subscriber_->RegisterStatsCallback(EventFwk::CommonEventSupport::COMMON_EVENT_SHUTDOWN,
                                       [this](const EventFwk::Want &want) { return UpdateStatsData(); });
    subscriber_->RegisterStatsCallback(
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED,
        [this](const EventFwk::Want &want) {
            uint32_t uid = want.GetIntParam(UID, 0);
            NETMGR_LOG_D("Net Manager delete uid, uid:[%{public}d]", uid);
            return CommonEventPackageRemoved(uid);
        });
    subscriber_->RegisterStatsCallback(
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED, [this](const EventFwk::Want &want) {
            uint32_t uid = want.GetIntParam(UID, 0);
            NETMGR_LOG_D("Net Manager add uid, uid:[%{public}d]", uid);
            return CommonEventPackageAdded(uid);
        });
    EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
}

void NetStatsService::GetDumpMessage(std::string &message)
{
    message.append("Net Stats Info:\n");
    uint64_t rxBytes = 0;
    uint64_t txBytes = 0;
    uint64_t rxPackets = 0;
    uint64_t txPackets = 0;
    NetsysController::GetInstance().GetTotalStats(rxBytes, static_cast<uint32_t>(StatsType::STATS_TYPE_RX_BYTES));
    NetsysController::GetInstance().GetTotalStats(txBytes, static_cast<uint32_t>(StatsType::STATS_TYPE_TX_BYTES));
    NetsysController::GetInstance().GetTotalStats(rxPackets, static_cast<uint32_t>(StatsType::STATS_TYPE_RX_PACKETS));
    NetsysController::GetInstance().GetTotalStats(txPackets, static_cast<uint32_t>(StatsType::STATS_TYPE_TX_PACKETS));

    message.append("\tRxBytes: " + std::to_string(rxBytes) + "\n");
    message.append("\tTxBytes: " + std::to_string(txBytes) + "\n");
    message.append("\tRxPackets: " + std::to_string(rxPackets) + "\n");
    message.append("\tTxPackets: " + std::to_string(txPackets) + "\n");
    std::for_each(BEAR_TYPE_LIST.begin(), BEAR_TYPE_LIST.end(), [&message, this](const auto &bearType) {
        std::list<std::string> ifaceNames;
        if (NetManagerCenter::GetInstance().GetIfaceNames(bearType, ifaceNames)) {
            return;
        }
        uint64_t rx = 0;
        uint64_t tx = 0;
        for (const auto &name : ifaceNames) {
            GetIfaceRxBytes(rx, name);
            GetIfaceTxBytes(tx, name);
            message.append("\t" + name + "-TxBytes: " + std::to_string(tx));
            message.append("\t" + name + "-RxBytes: " + std::to_string(rx));
        }
    });
}

bool NetStatsService::Init()
{
    if (!REGISTER_LOCAL_RESULT) {
        NETMGR_LOG_E("Register to local sa manager failed");
        registerToService_ = false;
        return false;
    }
    if (!registerToService_) {
        if (!Publish(DelayedSingleton<NetStatsService>::GetInstance().get())) {
            NETMGR_LOG_E("Register to sa manager failed");
            return false;
        }
        registerToService_ = true;
    }
    if (nullptr == netStatsCached_) {
        return false;
    }
    netStatsCached_->SetCallbackManager(netStatsCallback_);
    auto ret = netStatsCached_->StartCached();
    if (ret != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("Start cached failed");
        return false;
    }
    AddSystemAbilityListener(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    uint64_t delay = DELAY_US / 2;
    RefreshUidStatsFlag(delay);

    return true;
}

int32_t NetStatsService::RegisterNetStatsCallback(const sptr<INetStatsCallback> &callback)
{
    NETMGR_LOG_I("Enter RegisterNetStatsCallback");
    if (callback == nullptr) {
        NETMGR_LOG_E("RegisterNetStatsCallback parameter callback is null");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }
    netStatsCallback_->RegisterNetStatsCallback(callback);
    return NETMANAGER_SUCCESS;
}

int32_t NetStatsService::UnregisterNetStatsCallback(const sptr<INetStatsCallback> &callback)
{
    NETMGR_LOG_I("Enter UnregisterNetStatsCallback");
    if (callback == nullptr) {
        NETMGR_LOG_E("UnregisterNetStatsCallback parameter callback is null");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }
    netStatsCallback_->UnregisterNetStatsCallback(callback);
    return NETMANAGER_SUCCESS;
}

int32_t NetStatsService::GetIfaceRxBytes(uint64_t &stats, const std::string &interfaceName)
{
    return NetsysController::GetInstance().GetIfaceStats(stats, static_cast<uint32_t>(StatsType::STATS_TYPE_RX_BYTES),
                                                         interfaceName);
}

int32_t NetStatsService::GetIfaceTxBytes(uint64_t &stats, const std::string &interfaceName)
{
    return NetsysController::GetInstance().GetIfaceStats(stats, static_cast<uint32_t>(StatsType::STATS_TYPE_TX_BYTES),
                                                         interfaceName);
}

int32_t NetStatsService::GetCellularRxBytes(uint64_t &stats)
{
    std::list<std::string> ifaceNames;
    if (!GetIfaceNamesFromManager(ifaceNames)) {
        return STATS_ERR_GET_IFACE_NAME_FAILED;
    }

    for (const auto &name : ifaceNames) {
        uint64_t totalCellular = 0;
        auto ret = NetsysController::GetInstance().GetIfaceStats(
            totalCellular, static_cast<uint32_t>(StatsType::STATS_TYPE_RX_BYTES), name);
        if (ret != NETMANAGER_SUCCESS) {
            NETMGR_LOG_E("Get iface stats failed result: %{public}d", ret);
            return ret;
        }
        stats += totalCellular;
    }
    return NETMANAGER_SUCCESS;
}

int32_t NetStatsService::GetCellularTxBytes(uint64_t &stats)
{
    std::list<std::string> ifaceNames;
    if (!GetIfaceNamesFromManager(ifaceNames)) {
        return STATS_ERR_GET_IFACE_NAME_FAILED;
    }

    uint64_t totalCellular = 0;
    for (const auto &name : ifaceNames) {
        auto ret = NetsysController::GetInstance().GetIfaceStats(
            totalCellular, static_cast<uint32_t>(StatsType::STATS_TYPE_TX_BYTES), name);
        if (ret != NETMANAGER_SUCCESS) {
            NETMGR_LOG_E("Get iface stats failed result: %{public}d", ret);
            return ret;
        }
        stats += totalCellular;
    }
    return NETMANAGER_SUCCESS;
}

int32_t NetStatsService::GetAllRxBytes(uint64_t &stats)
{
    NETMGR_LOG_D("Enter GetAllRxBytes");
    return NetsysController::GetInstance().GetTotalStats(stats, static_cast<uint32_t>(StatsType::STATS_TYPE_RX_BYTES));
}

int32_t NetStatsService::GetAllTxBytes(uint64_t &stats)
{
    NETMGR_LOG_D("Enter GetAllTxBytes");
    return NetsysController::GetInstance().GetTotalStats(stats, static_cast<uint32_t>(StatsType::STATS_TYPE_TX_BYTES));
}

int32_t NetStatsService::GetUidRxBytes(uint64_t &stats, uint32_t uid)
{
    NETMGR_LOG_D("Enter GetUidRxBytes, uid is %{public}d", uid);
    return NetsysController::GetInstance().GetUidStats(stats, static_cast<uint32_t>(StatsType::STATS_TYPE_RX_BYTES),
                                                       uid);
}

int32_t NetStatsService::GetUidTxBytes(uint64_t &stats, uint32_t uid)
{
    NETMGR_LOG_D("Enter GetUidTxBytes,uid is %{public}d", uid);
    return NetsysController::GetInstance().GetUidStats(stats, static_cast<uint32_t>(StatsType::STATS_TYPE_TX_BYTES),
                                                       uid);
}

int32_t NetStatsService::GetIfaceStatsDetail(const std::string &iface, uint64_t start, uint64_t end,
                                             NetStatsInfo &statsInfo)
{
    // Start of get traffic data by interface name.
    NETMGR_LOG_D("Enter GetIfaceStatsDetail, iface= %{public}s", iface.c_str());
    NetmanagerHiTrace::NetmanagerStartSyncTrace("NetStatsService GetIfaceStatsDetail start");
    if (start > end) {
        NETMGR_LOG_E("start is after end.");
        return NETMANAGER_ERR_INVALID_PARAMETER;
    }
    std::vector<NetStatsInfo> allInfo;
    auto history = std::make_unique<NetStatsHistory>();
    int32_t ret = history->GetHistory(allInfo, iface, start, end);

    if (netStatsCached_ == nullptr) {
        NETMGR_LOG_E("netStatsCached_ is fail");
        return NETMANAGER_ERR_LOCAL_PTR_NULL;
    }
    netStatsCached_->GetIfaceStatsCached(allInfo);
    if (ret != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("Get traffic stats data failed");
        return ret;
    }
    std::for_each(allInfo.begin(), allInfo.end(), [&statsInfo, &iface, &start, &end](const auto &info) {
        if (info.iface_ == iface && info.date_ >= start && info.date_ <= end) {
            statsInfo += info;
        }
    });
    statsInfo.iface_ = iface;
    statsInfo.date_ = end;
    // End of get traffic data by interface name.
    NetmanagerHiTrace::NetmanagerStartSyncTrace("NetStatsService GetIfaceStatsDetail end");
    return NETMANAGER_SUCCESS;
}

int32_t NetStatsService::GetUidStatsDetail(const std::string &iface, uint32_t uid, uint64_t start, uint64_t end,
                                           NetStatsInfo &statsInfo)
{
    // Start of get traffic data by usr id.
    NETMGR_LOG_D("Enter GetIfaceStatsDetail, iface= %{public}s uid= %{public}d", iface.c_str(), uid);
    NetmanagerHiTrace::NetmanagerStartSyncTrace("NetStatsService GetUidStatsDetail start");
    if (start > end) {
        NETMGR_LOG_E("start is after end.");
        return NETMANAGER_ERR_INVALID_PARAMETER;
    }
    std::vector<NetStatsInfo> allInfo;
    auto history = std::make_unique<NetStatsHistory>();
    int32_t ret = history->GetHistory(allInfo, iface, uid, start, end);
    if (netStatsCached_ == nullptr) {
        NETMGR_LOG_E("netStatsCached_ is fail");
        return NETMANAGER_ERR_LOCAL_PTR_NULL;
    }
    netStatsCached_->GetUidStatsCached(allInfo);
    if (ret != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("Get traffic stats data failed");
        return ret;
    }
    std::for_each(allInfo.begin(), allInfo.end(), [&statsInfo, &iface, &uid, &start, &end](const auto &info) {
        if (info.iface_ == iface && info.uid_ == uid && info.date_ >= start && info.date_ <= end) {
            statsInfo += info;
        }
    });
    statsInfo.uid_ = uid;
    statsInfo.iface_ = iface;
    statsInfo.date_ = end;
    // End of get traffic data by usr id.
    NetmanagerHiTrace::NetmanagerFinishSyncTrace("NetStatsService GetUidStatsDetail end");
    return NETMANAGER_SUCCESS;
}

int32_t NetStatsService::UpdateIfacesStats(const std::string &iface, uint64_t start, uint64_t end,
                                           const NetStatsInfo &stats)
{
    // Start of update traffic data by date.
    NETMGR_LOG_I("UpdateIfacesStats ifaces is %{public}s", iface.c_str());
    NetmanagerHiTrace::NetmanagerStartSyncTrace("NetStatsService UpdateIfacesStats start");
    if (start > end) {
        NETMGR_LOG_E("start is after end.");
        return NETMANAGER_ERR_INVALID_PARAMETER;
    }
    std::vector<NetStatsInfo> infos;
    infos.push_back(stats);
    auto handler = std::make_unique<NetStatsDataHandler>();
    auto ret = handler->DeleteByDate(IFACE_TABLE, start, end);
    if (ret != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("Update ifaces stats failed");
    }
    ret = handler->WriteStatsData(infos, IFACE_TABLE);
    if (ret != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("Update ifaces stats failed");
        return STATS_ERR_WRITE_DATA_FAIL;
    }
    // End of update traffic data by date.
    NetmanagerHiTrace::NetmanagerFinishSyncTrace("NetStatsService UpdateIfacesStats end");
    return ret;
}

int32_t NetStatsService::UpdateStatsData()
{
    NETMGR_LOG_D("Enter UpdateStatsData.");
    if (netStatsCached_ == nullptr) {
        NETMGR_LOG_E("Cached is nullptr");
        return NETMANAGER_ERR_LOCAL_PTR_NULL;
    }
    netStatsCached_->ForceUpdateStats();
    NETMGR_LOG_D("End UpdateStatsData.");
    return NETMANAGER_SUCCESS;
}

int32_t NetStatsService::ResetFactory()
{
    auto handler = std::make_unique<NetStatsDataHandler>();
    return handler->ClearData();
}

int32_t NetStatsService::GetAllStatsInfo(std::vector<NetStatsInfo> &infos)
{
    NETMGR_LOG_D("Enter GetAllStatsInfo.");
    if (netStatsCached_ != nullptr) {
        netStatsCached_->GetUidPushStatsCached(infos);
        netStatsCached_->GetAllPushStatsCached(infos);
    } else {
        NETMGR_LOG_E("Cached is nullptr");
    }
    return NetsysController::GetInstance().GetAllStatsInfo(infos);
}

int32_t NetStatsService::GetAllSimStatsInfo(std::vector<NetStatsInfo> &infos)
{
    NETMGR_LOG_D("Enter GetAllSimStatsInfo.");
    return NetsysController::GetInstance().GetAllSimStatsInfo(infos);
}

int32_t NetStatsService::GetTrafficStatsByNetwork(std::unordered_map<uint32_t, NetStatsInfo> &infos,
                                                  const sptr<NetStatsNetwork> &network)
{
    NETMGR_LOG_D("Enter GetTrafficStatsByNetwork.");
    NetmanagerHiTrace::NetmanagerStartSyncTrace("NetStatsService GetTrafficStatsByNetwork start");
    if (netStatsCached_ == nullptr) {
        return NETMANAGER_ERR_LOCAL_PTR_NULL;
    }
    if (network == nullptr || network->startTime_ > network->endTime_) {
        NETMGR_LOG_E("param network is invalid");
        return NETMANAGER_ERR_INVALID_PARAMETER;
    }
    std::string ident;
    if (network->type_ == 0) {
        ident = std::to_string(network->simId_);
    }
    uint32_t start = network->startTime_;
    uint32_t end = network->endTime_;
    NETMGR_LOG_D("param: ident=%{public}s, start=%{public}u, end=%{public}u", ident.c_str(), start, end);
    auto history = std::make_unique<NetStatsHistory>();
    if (history == nullptr) {
        NETMGR_LOG_E("history is null");
        return NETMANAGER_ERR_INTERNAL;
    }
    std::vector<NetStatsInfo> allInfo;
    int32_t ret = history->GetHistoryByIdent(allInfo, ident, start, end);
    if (ret != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("get history by ident failed, err code=%{public}d", ret);
        return ret;
    }
    netStatsCached_->GetKernelStats(allInfo);
    netStatsCached_->GetUidPushStatsCached(allInfo);
    netStatsCached_->GetUidStatsCached(allInfo);
    netStatsCached_->GetUidSimStatsCached(allInfo);
    std::for_each(allInfo.begin(), allInfo.end(), [&infos, &ident, &start, &end](NetStatsInfo &info) {
        if (ident != info.ident_ || start > info.date_ || end < info.date_) {
            return;
        }
        if (info.flag_ == STATS_DATA_FLAG_UNINSTALLED) {
            info.uid_ = UNINSTALLED_UID;
        }
        auto item = infos.find(info.uid_);
        if (item == infos.end()) {
            infos.emplace(info.uid_, info);
        } else {
            item->second += info;
        }
    });
    NetmanagerHiTrace::NetmanagerStartSyncTrace("NetStatsService GetTrafficStatsByNetwork end");
    return NETMANAGER_SUCCESS;
}

int32_t NetStatsService::GetTrafficStatsByUidNetwork(std::vector<NetStatsInfoSequence> &infos, uint32_t uid,
                                                     const sptr<NetStatsNetwork> &network)
{
    NETMGR_LOG_D("Enter GetTrafficStatsByUidNetwork.");
    NetmanagerHiTrace::NetmanagerStartSyncTrace("NetStatsService GetTrafficStatsByUidNetwork start");
    if (netStatsCached_ == nullptr) {
        NETMGR_LOG_E("Cached is nullptr");
        return NETMANAGER_ERR_LOCAL_PTR_NULL;
    }
    if (network == nullptr || network->startTime_ > network->endTime_) {
        NETMGR_LOG_E("param network is invalid");
        return NETMANAGER_ERR_INVALID_PARAMETER;
    }
    std::string ident;
    if (network->type_ == 0) {
        ident = std::to_string(network->simId_);
    }
    uint32_t start = network->startTime_;
    uint32_t end = network->endTime_;
    NETMGR_LOG_D("GetTrafficStatsByUidNetwork param: "
        "uid=%{public}u, ident=%{public}s, start=%{public}u, end=%{public}u", uid, ident.c_str(), start, end);
    auto history = std::make_unique<NetStatsHistory>();
    if (history == nullptr) {
        NETMGR_LOG_E("history is null");
        return NETMANAGER_ERR_INTERNAL;
    }
    std::vector<NetStatsInfo> allInfo;
    int32_t ret = history->GetHistory(allInfo, uid, ident, start, end);
    if (ret != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("get history by uid and ident failed, err code=%{public}d", ret);
        return ret;
    }
    netStatsCached_->GetKernelStats(allInfo);
    netStatsCached_->GetUidPushStatsCached(allInfo);
    netStatsCached_->GetUidStatsCached(allInfo);
    netStatsCached_->GetUidSimStatsCached(allInfo);
    std::for_each(allInfo.begin(), allInfo.end(), [this, &infos, &uid, &ident, &start, &end](const NetStatsInfo &info) {
        if (uid != info.uid_ || ident != info.ident_ || start > info.date_ || end < info.date_) {
            return;
        }
        if (info.flag_ == STATS_DATA_FLAG_UNINSTALLED) {
            return;
        }
        MergeTrafficStats(infos, info, end);
    });
    NetmanagerHiTrace::NetmanagerStartSyncTrace("NetStatsService GetTrafficStatsByUidNetwork end");
    return NETMANAGER_SUCCESS;
}

int32_t NetStatsService::SetAppStats(const PushStatsInfo &info)
{
    NETMGR_LOG_D("Enter GetTrafficStatsByUidNetwork.");
    NetmanagerHiTrace::NetmanagerStartSyncTrace("NetStatsService SetAppStats start");
    if (netStatsCached_ == nullptr) {
        NETMGR_LOG_E("Cached is nullptr");
        return NETMANAGER_ERR_LOCAL_PTR_NULL;
    }
    netStatsCached_->SetAppStats(info);
    NetmanagerHiTrace::NetmanagerStartSyncTrace("NetStatsService SetAppStats end");
    return NETMANAGER_SUCCESS;
}

int32_t NetStatsService::GetCookieRxBytes(uint64_t &stats, uint64_t cookie)
{
    return NetsysController::GetInstance().GetCookieStats(stats, static_cast<uint32_t>(StatsType::STATS_TYPE_RX_BYTES),
                                                          cookie);
}

int32_t NetStatsService::GetCookieTxBytes(uint64_t &stats, uint64_t cookie)
{
    return NetsysController::GetInstance().GetCookieStats(stats, static_cast<uint32_t>(StatsType::STATS_TYPE_TX_BYTES),
                                                          cookie);
}

void NetStatsService::MergeTrafficStats(std::vector<NetStatsInfoSequence> &statsInfoSequences, const NetStatsInfo &info,
                                        uint32_t currentTimestamp)
{
    NetStatsInfoSequence tmp;
    tmp.startTime_ = info.date_;
    tmp.endTime_ = info.date_;
    tmp.info_ = info;
    uint32_t previousTimestamp = currentTimestamp > DAY_SECONDS ? currentTimestamp - DAY_SECONDS : 0;
    if (info.date_ > previousTimestamp) {
        statsInfoSequences.push_back(std::move(tmp));
        return;
    }
    auto findRet = std::find_if(
        statsInfoSequences.begin(), statsInfoSequences.end(), [&info, previousTimestamp](const auto &item) {
            return item.endTime_ < previousTimestamp && CommonUtils::IsSameNaturalDay(info.date_, item.endTime_);
        });
    if (findRet == statsInfoSequences.end()) {
        statsInfoSequences.push_back(std::move(tmp));
        return;
    }
    (*findRet).info_ += info;
}

bool NetStatsService::GetIfaceNamesFromManager(std::list<std::string> &ifaceNames)
{
    int32_t ret = NetManagerCenter::GetInstance().GetIfaceNames(BEARER_CELLULAR, ifaceNames);
    if (ret != NETMANAGER_SUCCESS || ifaceNames.empty()) {
        NETMGR_LOG_D("Iface list is empty, ret = %{public}d", ret);
        return false;
    }
    return true;
}

std::unordered_map<uint32_t, SampleBundleInfo> NetStatsService::GetSampleBundleInfosForActiveUser()
{
    void *handler = dlopen(LIB_NET_BUNDLE_UTILS_PATH.c_str(), RTLD_LAZY | RTLD_NODELETE);
    if (handler == nullptr) {
        NETMGR_LOG_E("load lib failed, reason : %{public}s", dlerror());
        return std::unordered_map<uint32_t, SampleBundleInfo>{};
    }
    using GetNetBundleClass = INetBundle *(*)();
    auto getNetBundle = (GetNetBundleClass)dlsym(handler, "GetNetBundle");
    if (getNetBundle == nullptr) {
        NETMGR_LOG_E("GetNetBundle failed, reason : %{public}s", dlerror());
        dlclose(handler);
        return std::unordered_map<uint32_t, SampleBundleInfo>{};
    }
    auto netBundle = getNetBundle();
    if (netBundle == nullptr) {
        NETMGR_LOG_E("netBundle is nullptr");
        dlclose(handler);
        return std::unordered_map<uint32_t, SampleBundleInfo>{};
    }
    std::optional<std::unordered_map<uint32_t, SampleBundleInfo>> result = netBundle->ObtainBundleInfoForActive();
    dlclose(handler);
    if (!result.has_value()) {
        NETMGR_LOG_W("ObtainBundleInfoForActive is nullopt");
        return std::unordered_map<uint32_t, SampleBundleInfo>{};
    }
    return result.value();
}

SampleBundleInfo NetStatsService::GetSampleBundleInfoForUid(uint32_t uid)
{
    void *handler = dlopen(LIB_NET_BUNDLE_UTILS_PATH.c_str(), RTLD_LAZY | RTLD_NODELETE);
    if (handler == nullptr) {
        NETMGR_LOG_E("load lib failed, reason : %{public}s", dlerror());
        return SampleBundleInfo{};
    }
    using GetNetBundleClass = INetBundle *(*)();
    auto getNetBundle = (GetNetBundleClass)dlsym(handler, "GetNetBundle");
    if (getNetBundle == nullptr) {
        NETMGR_LOG_E("GetNetBundle failed, reason : %{public}s", dlerror());
        dlclose(handler);
        return SampleBundleInfo{};
    }
    auto netBundle = getNetBundle();
    if (netBundle == nullptr) {
        NETMGR_LOG_E("netBundle is nullptr");
        dlclose(handler);
        return SampleBundleInfo{};
    }
    std::optional<SampleBundleInfo> result = netBundle->ObtainBundleInfoForUid(uid);
    dlclose(handler);
    if (!result.has_value()) {
        NETMGR_LOG_W("ObtainBundleInfoForUid is nullopt");
        return SampleBundleInfo{};
    }
    return result.value();
}

void NetStatsService::RefreshUidStatsFlag(uint64_t delay)
{
    std::function<void()> uidInstallSourceFunc = [this]() {
        auto tmp = GetSampleBundleInfosForActiveUser();
        for (auto iter = tmp.begin(); iter != tmp.end(); ++iter) {
            if (CommonUtils::IsSim(iter->second.bundleName_) ||
                CommonUtils::IsSim2(iter->second.bundleName_)) {
                netStatsCached_->SetUidSimSampleBundle(iter->first, iter->second);
            }
        }
        netStatsCached_->ClearUidStatsFlag();
        netStatsCached_->SetUidStatsFlag(tmp);
    };
    ffrt::submit(std::move(uidInstallSourceFunc), {}, {}, ffrt::task_attr().name("RefreshUidStatsFlag").delay(delay));
}

bool NetStatsService::CommonEventPackageAdded(uint32_t uid)
{
    SampleBundleInfo sampleBundleInfo = GetSampleBundleInfoForUid(uid);
    if (CommonUtils::IsSim(sampleBundleInfo.bundleName_) ||
        CommonUtils::IsSim2(sampleBundleInfo.bundleName_)) {
        uint64_t delay = 0;
        if (netStatsCached_->GetUidSimSampleBundlesSize() == 0) {
            delay = DELAY_US;
            netStatsCached_->ForceCachedStats();
        }
        RefreshUidStatsFlag(delay);
    } else {
        std::unordered_map<uint32_t, SampleBundleInfo> tmp{{uid, sampleBundleInfo}};
        netStatsCached_->SetUidStatsFlag(tmp);
    }
    return true;
}

bool NetStatsService::CommonEventPackageRemoved(uint32_t uid)
{
    auto handler = std::make_unique<NetStatsDataHandler>();
    if (handler == nullptr) {
        NETMGR_LOG_E("Net Manager package removed, get db handler failed. uid:[%{public}d]", uid);
        return static_cast<int32_t>(NETMANAGER_ERR_INTERNAL);
    }
    auto ret1 = handler->UpdateStatsFlag(uid, STATS_DATA_FLAG_UNINSTALLED);
    if (ret1 != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("Net Manager update stats flag failed, uid:[%{public}d]", uid);
    }
    auto ret2 = handler->UpdateSimStatsFlag(uid, STATS_DATA_FLAG_UNINSTALLED);
    if (ret2 != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("Net Manager update sim stats flag failed, uid:[%{public}d]", uid);
    }
    auto ffrtHandle = netStatsCached_->ForceArchiveStats(uid);
    if (netStatsCached_->GetUidSimSampleBundle(uid).has_value()) {
        ffrt::wait({ffrtHandle});
        RefreshUidStatsFlag(0);
    }
    return ret1 != NETMANAGER_SUCCESS ? ret1 : ret2;
}
} // namespace NetManagerStandard
} // namespace OHOS

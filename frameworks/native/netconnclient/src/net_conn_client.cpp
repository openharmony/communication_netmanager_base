/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "net_conn_client.h"
#include <thread>
#include <dlfcn.h>

#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "fwmark_client.h"
#include "net_conn_service_proxy.h"
#include "net_manager_constants.h"
#include "net_mgr_log_wrapper.h"
#include "net_bundle.h"
#include "net_supplier_callback_stub.h"
#include "netsys_sock_client.h"
#include "system_ability_status_change_stub.h"
#include "netmanager_base_permission.h"
#ifndef NETMANAGER_TEST
#include "ffrt.h"
#endif

static constexpr const int32_t MIN_VALID_NETID = 100;
static constexpr const int32_t MIN_VALID_INTERNAL_NETID = 1;
static constexpr const int32_t MAX_VALID_INTERNAL_NETID = 50;
static const std::string LIB_NET_BUNDLE_UTILS_PATH = "libnet_bundle_utils.z.so";

namespace OHOS {
namespace NetManagerStandard {
class NetConnAbilityListener : public SystemAbilityStatusChangeStub {
public:
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
private:
    std::mutex mutex_;
};
NetConnClient::NetConnClient() : NetConnService_(nullptr), deathRecipient_(nullptr), saStatusListener_(nullptr)
{
    defaultNetSpecifier_ = sptr<NetSpecifier>::MakeSptr();
    defaultNetSpecifier_->SetCapabilities({NET_CAPABILITY_INTERNET, NET_CAPABILITY_NOT_VPN});
}

NetConnClient::~NetConnClient()
{
    DlCloseRemoveDeathRecipient();
}

NetConnClient &NetConnClient::GetInstance()
{
    static std::shared_ptr<NetConnClient> instance = std::make_shared<NetConnClient>();
    return *instance;
}

void NetConnClient::SubscribeSystemAbility()
{
    if (saStatusListener_ != nullptr) {
        NETMGR_LOG_D("No duplicate subscribe.");
        return;
    }
    saStatusListener_ = sptr<NetConnAbilityListener>(new NetConnAbilityListener());
    if (saStatusListener_ == nullptr) {
        NETMGR_LOG_E("NetConnAbilityListener create failed.");
        return;
    }
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        NETMGR_LOG_E("SubscribeSystemAbility sam is null.");
        return;
    }
    int32_t result =
        sam->SubscribeSystemAbility(static_cast<int32_t>(COMM_NET_CONN_MANAGER_SYS_ABILITY_ID), saStatusListener_);
    if (result != ERR_OK) {
        NETMGR_LOG_E("NetConnAbilityListener subscribe failed, code %{public}d.", result);
    }
}

void NetConnClient::UnsubscribeSystemAbility()
{
    if (saStatusListener_ == nullptr) {
        NETMGR_LOG_I("NetConnAbilityListener is nullptr.");
        return;
    }
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        NETMGR_LOG_E("UnsubscribeSystemAbility sam is null.");
        return;
    }
    int32_t result =
        sam->UnSubscribeSystemAbility(static_cast<int32_t>(COMM_NET_CONN_MANAGER_SYS_ABILITY_ID), saStatusListener_);
    if (result != ERR_OK) {
        NETMGR_LOG_E("NetConnAbilityListener Unsubscribe failed, code %{public}d.", result);
    }
}

void NetConnAbilityListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    std::lock_guard<std::mutex>(this->mutex_);
    if (systemAbilityId == COMM_NET_CONN_MANAGER_SYS_ABILITY_ID) {
        NETMGR_LOG_I("net conn manager sa is added.");
        NetConnClient::GetInstance().RecoverCallbackAndGlobalProxy();
        NetConnClient::GetInstance().UnsubscribeSystemAbility();
    }
}

void NetConnAbilityListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    std::lock_guard<std::mutex>(this->mutex_);
    if (systemAbilityId == COMM_NET_CONN_MANAGER_SYS_ABILITY_ID) {
        NETMGR_LOG_I("net conn manager sa is removed.");
    }
}

int32_t NetConnClient::SystemReady()
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->SystemReady();
}

int32_t NetConnClient::SetInternetPermission(uint32_t uid, uint8_t allow)
{
    uint8_t oldAllow;
    bool ret = netPermissionMap_.Find(uid, oldAllow);
    if (ret && allow == oldAllow) {
        return NETMANAGER_SUCCESS;
    }

    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    int32_t result = proxy->SetInternetPermission(uid, allow);
    if (result == NETMANAGER_SUCCESS) {
        netPermissionMap_.EnsureInsert(uid, allow);
    }
    return result;
}

int32_t NetConnClient::EnableVnicNetwork(const sptr<NetLinkInfo> &netLinkInfo, const std::set<int32_t> &uids)
{
    NETMGR_LOG_D("EnableVnicNetwork client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->EnableVnicNetwork(netLinkInfo, uids);
}

int32_t NetConnClient::DisableVnicNetwork()
{
    NETMGR_LOG_D("DisableVnicNetwork client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->DisableVnicNetwork();
}

int32_t NetConnClient::EnableDistributedClientNet(const std::string &virnicAddr, const std::string &iif)
{
    NETMGR_LOG_D("EnableDistributedClientNet client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->EnableDistributedClientNet(virnicAddr, iif);
}

int32_t NetConnClient::EnableDistributedServerNet(const std::string &iif, const std::string &devIface,
                                                  const std::string &dstAddr)
{
    NETMGR_LOG_D("EnableDistributedServerNet client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->EnableDistributedServerNet(iif, devIface, dstAddr);
}

int32_t NetConnClient::DisableDistributedNet(bool isServer)
{
    NETMGR_LOG_D("DisableDistributedNet client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->DisableDistributedNet(isServer);
}

int32_t NetConnClient::RegisterNetSupplier(NetBearType bearerType, const std::string &ident,
                                           const std::set<NetCap> &netCaps, uint32_t &supplierId)
{
    NETMGR_LOG_D("RegisterNetSupplier client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->RegisterNetSupplier(bearerType, ident, netCaps, supplierId);
}

int32_t NetConnClient::UnregisterNetSupplier(uint32_t supplierId)
{
    NETMGR_LOG_D("UnregisterNetSupplier client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    {
        std::lock_guard<std::mutex> lock(netSupplierCallbackMutex_);
        netSupplierCallback_.erase(supplierId);
    }
    return proxy->UnregisterNetSupplier(supplierId);
}

int32_t NetConnClient::RegisterNetSupplierCallback(uint32_t supplierId, const sptr<NetSupplierCallbackBase> &callback)
{
    NETMGR_LOG_D("RegisterNetSupplierCallback client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    sptr<NetSupplierCallbackStub> ptr = std::make_unique<NetSupplierCallbackStub>().release();
    ptr->RegisterSupplierCallbackImpl(callback);
    {
        std::lock_guard<std::mutex> lock(netSupplierCallbackMutex_);
        netSupplierCallback_[supplierId] = ptr;
    }
    return proxy->RegisterNetSupplierCallback(supplierId, ptr);
}

int32_t NetConnClient::RegisterNetConnCallback(const sptr<INetConnCallback> callback)
{
    return RegisterNetConnCallback(defaultNetSpecifier_, callback, 0);
}

int32_t NetConnClient::RegisterNetConnCallback(const sptr<NetSpecifier> &netSpecifier,
                                               const sptr<INetConnCallback> callback, const uint32_t &timeoutMS)
{
    NETMGR_LOG_D("RegisterNetConnCallback with timeout client in.");
    if (netSpecifier == nullptr || !netSpecifier->SpecifierIsValid()) {
        NETMGR_LOG_E("The parameter of netSpecifier is invalid");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("The parameter of proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    int32_t ret = NETMANAGER_SUCCESS;
    std::unique_lock<std::shared_mutex> locker(netConnCallbackManagerMapMutex_);
    auto it = netConnCallbackManagerMap_.find(netSpecifier);
    if (it != netConnCallbackManagerMap_.end()) {
        it->second->AddNetConnCallback(callback);
    } else {
        auto cb = sptr<NetConnCallbackManager>::MakeSptr();
        cb->AddNetConnCallback(callback);
        ret = proxy->RegisterNetConnCallback(netSpecifier, cb, timeoutMS);
        if (ret == NETMANAGER_SUCCESS) {
            netConnCallbackManagerMap_.emplace(netSpecifier, cb);
            NETMGR_LOG_D("RegisterNetConnCallback success, save callback.");
        }
    }

    return ret;
}

int32_t NetConnClient::RequestNetConnection(const sptr<NetSpecifier> netSpecifier,
                                            const sptr<INetConnCallback> callback, const uint32_t timeoutMS)
{
    NETMGR_LOG_D("RequestNetConnection with timeout client in.");
    if (netSpecifier == nullptr || !netSpecifier->SpecifierIsValid()) {
        NETMGR_LOG_E("The parameter of netSpecifier is invalid");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("The parameter of proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    int32_t ret = NETMANAGER_SUCCESS;
    std::unique_lock<std::shared_mutex> locker(netConnCallbackManagerMapMutex_);
    auto it = systemNetConnCallbackManagerMap_.find(netSpecifier);
    if (it != systemNetConnCallbackManagerMap_.end()) {
        it->second->AddNetConnCallback(callback);
    } else {
        auto cb = sptr<NetConnCallbackManager>::MakeSptr();
        cb->AddNetConnCallback(callback);
        ret = proxy->RequestNetConnection(netSpecifier, cb, timeoutMS);
        if (ret == NETMANAGER_SUCCESS) {
            systemNetConnCallbackManagerMap_.emplace(netSpecifier, cb);
            NETMGR_LOG_D("RegisterNetConnCallback success, save callback.");
        }
    }

    return ret;
}

int32_t NetConnClient::UnregisterNetConnCallback(const sptr<INetConnCallback> &callback)
{
    NETMGR_LOG_D("UnregisterNetConnCallback client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    std::unique_lock<std::shared_mutex> locker(netConnCallbackManagerMapMutex_);
    int32_t ret1 = UnRegisterNetConnCallbackManager(callback, netConnCallbackManagerMap_);
    int32_t ret2 = UnRegisterNetConnCallbackManager(callback, systemNetConnCallbackManagerMap_);
    return (ret1 == NETMANAGER_SUCCESS && ret2 == NETMANAGER_SUCCESS) ? NETMANAGER_SUCCESS :
        (ret1 == NETMANAGER_SUCCESS ? ret2 : ret1);
}

int32_t NetConnClient::RegisterNetDetectionCallback(int32_t netId, const sptr<INetDetectionCallback> &callback)
{
    NETMGR_LOG_I("RegisterNetDetectionCallback client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->RegisterNetDetectionCallback(netId, callback);
}

int32_t NetConnClient::UnRegisterNetDetectionCallback(int32_t netId, const sptr<INetDetectionCallback> &callback)
{
    NETMGR_LOG_I("UnRegisterNetDetectionCallback client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->UnRegisterNetDetectionCallback(netId, callback);
}

int32_t NetConnClient::UpdateNetCaps(const std::set<NetCap> &netCaps, const uint32_t supplierId)
{
    NETMGR_LOG_I("Update net caps.");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->UpdateNetCaps(netCaps, supplierId);
}

int32_t NetConnClient::UpdateNetSupplierInfo(uint32_t supplierId, const sptr<NetSupplierInfo> &netSupplierInfo)
{
    NETMGR_LOG_I("UpdateNetSupplierInfo client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->UpdateNetSupplierInfo(supplierId, netSupplierInfo);
}

int32_t NetConnClient::UpdateNetLinkInfo(uint32_t supplierId, const sptr<NetLinkInfo> &netLinkInfo)
{
    NETMGR_LOG_I("UpdateNetLinkInfo client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->UpdateNetLinkInfo(supplierId, netLinkInfo);
}

int32_t NetConnClient::GetDefaultNet(NetHandle &netHandle)
{
    NETMGR_LOG_D("GetDefaultNet client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    int32_t netId = 0;
    int32_t result = proxy->GetDefaultNet(netId);
    if (result != NETMANAGER_SUCCESS) {
        NETMGR_LOG_D("fail to get default net.");
        return result;
    }
    netHandle.SetNetId(netId);
    NETMGR_LOG_D("GetDefaultNet client out.");
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::HasDefaultNet(bool &flag)
{
    NETMGR_LOG_D("HasDefaultNet client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->HasDefaultNet(flag);
}

int32_t NetConnClient::GetAllNets(std::list<sptr<NetHandle>> &netList)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    std::list<int32_t> netIdList;
    int32_t result = proxy->GetAllNets(netIdList);
    if (result != NETMANAGER_SUCCESS) {
        return result;
    }
    std::list<int32_t>::iterator iter;
    for (iter = netIdList.begin(); iter != netIdList.end(); ++iter) {
        sptr<NetHandle> netHandle = std::make_unique<NetHandle>(*iter).release();
        if (netHandle != nullptr) {
            netList.push_back(netHandle);
        }
    }
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::GetConnectionProperties(const NetHandle &netHandle, NetLinkInfo &info)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->GetConnectionProperties(netHandle.GetNetId(), info);
}

int32_t NetConnClient::GetNetCapabilities(const NetHandle &netHandle, NetAllCapabilities &netAllCap)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->GetNetCapabilities(netHandle.GetNetId(), netAllCap);
}

int32_t NetConnClient::GetAddressesByName(const std::string &host, int32_t netId, std::vector<INetAddr> &addrList)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->GetAddressesByName(host, netId, addrList);
}

int32_t NetConnClient::GetAddressByName(const std::string &host, int32_t netId, INetAddr &addr)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->GetAddressByName(host, netId, addr);
}

int32_t NetConnClient::GetIfaceNameIdentMaps(NetBearType bearerType,
                                             SafeMap<std::string, std::string> &ifaceNameIdentMaps)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->GetIfaceNameIdentMaps(bearerType, ifaceNameIdentMaps);
}

int32_t NetConnClient::BindSocket(int32_t socketFd, int32_t netId)
{
    // default netId begin whit 100, inner virtual interface netId between 1 and 50
    if (netId < MIN_VALID_INTERNAL_NETID || (netId > MAX_VALID_INTERNAL_NETID && netId < MIN_VALID_NETID)) {
        NETMGR_LOG_E("netId is invalid.");
        return NET_CONN_ERR_INVALID_NETWORK;
    }
    std::shared_ptr<nmd::FwmarkClient> fwmarkClient_ = std::make_shared<nmd::FwmarkClient>();
    if (fwmarkClient_ == nullptr) {
        NETMGR_LOG_E("fwmarkClient_ is nullptr");
        return NETMANAGER_ERR_PARAMETER_ERROR;
    }
    fwmarkClient_->BindSocket(socketFd, netId);
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::NetDetection(const NetHandle &netHandle)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->NetDetection(netHandle.GetNetId());
}

sptr<INetConnService> NetConnClient::GetProxy()
{
    std::lock_guard lock(mutex_);

    if (NetConnService_) {
        NETMGR_LOG_D("get proxy is ok");
        return NetConnService_;
    }

    NETMGR_LOG_D("execute GetSystemAbilityManager");
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        NETMGR_LOG_E("GetProxy(), get SystemAbilityManager failed");
        return nullptr;
    }

    sptr<IRemoteObject> remote = sam->CheckSystemAbility(COMM_NET_CONN_MANAGER_SYS_ABILITY_ID);
    if (remote == nullptr) {
        NETMGR_LOG_E("get Remote service failed");
        return nullptr;
    }

    deathRecipient_ = new (std::nothrow) NetConnDeathRecipient(*this);
    if (deathRecipient_ == nullptr) {
        NETMGR_LOG_E("get deathRecipient_ failed");
        return nullptr;
    }
    if ((remote->IsProxyObject()) && (!remote->AddDeathRecipient(deathRecipient_))) {
        NETMGR_LOG_E("add death recipient failed");
        return nullptr;
    }

    NetConnService_ = iface_cast<INetConnService>(remote);
    if (NetConnService_ == nullptr) {
        NETMGR_LOG_E("get Remote service proxy failed");
        return nullptr;
    }

    return NetConnService_;
}

int32_t NetConnClient::SetAirplaneMode(bool state)
{
    NETMGR_LOG_I("SetAirplaneMode client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->SetAirplaneMode(state);
}

void NetConnClient::RecoverCallbackAndGlobalProxy()
{
    if (globalHttpProxy_.GetHost().empty() && preAirplaneCallback_ == nullptr) {
        NETMGR_LOG_W("no need recovery");
        return;
    }
    std::shared_lock<std::shared_mutex> locker(netConnCallbackManagerMapMutex_);
    RecoverCallbackAndGlobalProxy(netConnCallbackManagerMap_);
    RecoverCallbackAndGlobalProxy(systemNetConnCallbackManagerMap_);
    locker.unlock();

    auto proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return;
    }
    if (preAirplaneCallback_ != nullptr) {
        int32_t ret = proxy->RegisterPreAirplaneCallback(preAirplaneCallback_);
        NETMGR_LOG_D("Register pre airplane result %{public}d", ret);
    }

    if (!globalHttpProxy_.GetHost().empty()) {
        int32_t ret = proxy->SetGlobalHttpProxy(globalHttpProxy_);
        NETMGR_LOG_D("globalHttpProxy_ Register result %{public}d", ret);
    }
}

void NetConnClient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    NETMGR_LOG_D("on remote died");
    if (remote == nullptr) {
        NETMGR_LOG_E("remote object is nullptr");
        return;
    }

    std::lock_guard lock(mutex_);
    if (NetConnService_ == nullptr) {
        NETMGR_LOG_E("NetConnService_ is nullptr");
        return;
    }

    sptr<IRemoteObject> local = NetConnService_->AsObject();
    if (local != remote.promote()) {
        NETMGR_LOG_E("proxy and stub is not same remote object");
        return;
    }

    local->RemoveDeathRecipient(deathRecipient_);
    NetConnService_ = nullptr;
    SubscribeSystemAbility();
}

void NetConnClient::DlCloseRemoveDeathRecipient()
{
    UnsubscribeSystemAbility();
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return;
    }

    auto serviceRemote = proxy->AsObject();
    if (serviceRemote == nullptr) {
        NETMGR_LOG_E("serviceRemote is nullptr");
        return;
    }

    serviceRemote->RemoveDeathRecipient(deathRecipient_);
    NETMGR_LOG_I("RemoveDeathRecipient success");
}

int32_t NetConnClient::IsDefaultNetMetered(bool &isMetered)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->IsDefaultNetMetered(isMetered);
}

int32_t NetConnClient::SetGlobalHttpProxy(const HttpProxy &httpProxy)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    if (globalHttpProxy_ != httpProxy) {
        globalHttpProxy_ = httpProxy;
    }
    return proxy->SetGlobalHttpProxy(httpProxy);
}

void NetConnClient::RegisterAppHttpProxyCallback(std::function<void(const HttpProxy &httpProxy)> callback,
                                                 uint32_t &callbackid)
{
    std::lock_guard<std::mutex> lock(appHttpProxyCbMapMutex_);
    uint32_t id = currentCallbackId_;
    currentCallbackId_++;
    appHttpProxyCbMap_[id] = callback;
    callbackid = id;
    if (callback && !appHttpProxy_.GetHost().empty()) {
        callback(appHttpProxy_);
    }
    NETMGR_LOG_I("registerCallback id:%{public}d.", id);
}

void NetConnClient::UnregisterAppHttpProxyCallback(uint32_t callbackid)
{
    NETMGR_LOG_I("unregisterCallback callbackid:%{public}d.", callbackid);
    std::lock_guard<std::mutex> lock(appHttpProxyCbMapMutex_);
    appHttpProxyCbMap_.erase(callbackid);
}

int32_t NetConnClient::SetAppHttpProxy(const HttpProxy &httpProxy)
{
    NETMGR_LOG_I("Enter AppHttpProxy");

    if (appHttpProxy_ != httpProxy) {
        appHttpProxy_ = httpProxy;
        std::lock_guard<std::mutex> lock(appHttpProxyCbMapMutex_);
        for (const auto &pair : appHttpProxyCbMap_) {
            pair.second(httpProxy);
        }
    }

    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::GetGlobalHttpProxy(HttpProxy &httpProxy)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->GetGlobalHttpProxy(httpProxy);
}

int32_t NetConnClient::GetDefaultHttpProxy(HttpProxy &httpProxy)
{
    if (!appHttpProxy_.GetHost().empty()) {
        httpProxy = appHttpProxy_;
        NETMGR_LOG_D("Return AppHttpProxy:%{public}s:%{public}d",
                     httpProxy.GetHost().c_str(), httpProxy.GetPort());
        return NETMANAGER_SUCCESS;
    }

    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    int32_t bindNetId = 0;
    GetAppNet(bindNetId);
    return proxy->GetDefaultHttpProxy(bindNetId, httpProxy);
}

int32_t NetConnClient::SetPacUrl(const std::string &pacUrl)
{
    NETMGR_LOG_I("Enter SetPacUrl");

    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->SetPacUrl(pacUrl);
}

int32_t NetConnClient::GetPacUrl(std::string &pacUrl)
{
    NETMGR_LOG_I("Enter GetPacUrl");

    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->GetPacUrl(pacUrl);
}

int32_t NetConnClient::QueryTraceRoute(
    const std::string &destination, int32_t maxJumpNumber, int32_t packetsType, std::string &traceRouteInfo)
{
    NETMGR_LOG_D("Enter QueryTraceRoute");

    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->QueryTraceRoute(destination, maxJumpNumber, packetsType, traceRouteInfo);
}

int32_t NetConnClient::GetNetIdByIdentifier(const std::string &ident, std::list<int32_t> &netIdList)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->GetNetIdByIdentifier(ident, netIdList);
}

int32_t NetConnClient::SetAppNet(int32_t netId)
{
    if (netId < MIN_VALID_NETID && netId != 0) {
        return NET_CONN_ERR_INVALID_NETWORK;
    }
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    int32_t ret = proxy->SetAppNet(netId);
    if (ret != NETMANAGER_SUCCESS) {
        return ret;
    }

    SetNetForApp(netId);
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::GetAppNet(int32_t &netId)
{
    netId = GetNetForApp();
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::RegisterNetInterfaceCallback(const sptr<INetInterfaceStateCallback> &callback)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->RegisterNetInterfaceCallback(callback);
}

int32_t NetConnClient::UnregisterNetInterfaceCallback(const sptr<INetInterfaceStateCallback> &callback)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->UnregisterNetInterfaceCallback(callback);
}

int32_t NetConnClient::GetNetInterfaceConfiguration(const std::string &iface, NetInterfaceConfiguration &config)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->GetNetInterfaceConfiguration(iface, config);
}

int32_t NetConnClient::SetNetInterfaceIpAddress(const std::string &iface, const std::string &ipAddress)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->SetNetInterfaceIpAddress(iface, ipAddress);
}

int32_t NetConnClient::SetInterfaceUp(const std::string &iface)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->SetInterfaceUp(iface);
}

int32_t NetConnClient::SetInterfaceDown(const std::string &iface)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->SetInterfaceDown(iface);
}

int32_t NetConnClient::AddNetworkRoute(int32_t netId, const std::string &ifName,
                                       const std::string &destination, const std::string &nextHop)
{
    NETMGR_LOG_I("AddNetworkRoute client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->AddNetworkRoute(netId, ifName, destination, nextHop);
}

int32_t NetConnClient::RemoveNetworkRoute(int32_t netId, const std::string &ifName,
                                          const std::string &destination, const std::string &nextHop)
{
    NETMGR_LOG_I("RemoveNetworkRoute client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->RemoveNetworkRoute(netId, ifName, destination, nextHop);
}

int32_t NetConnClient::AddInterfaceAddress(const std::string &ifName, const std::string &ipAddr,
                                           int32_t prefixLength)
{
    NETMGR_LOG_I("AddInterfaceAddress client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->AddInterfaceAddress(ifName, ipAddr, prefixLength);
}

int32_t NetConnClient::DelInterfaceAddress(const std::string &ifName, const std::string &ipAddr,
                                           int32_t prefixLength)
{
    NETMGR_LOG_I("DelInterfaceAddress client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->DelInterfaceAddress(ifName, ipAddr, prefixLength);
}

int32_t NetConnClient::AddStaticArp(const std::string &ipAddr, const std::string &macAddr, const std::string &ifName)
{
    NETMGR_LOG_I("AddStaticArp client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->AddStaticArp(ipAddr, macAddr, ifName);
}

int32_t NetConnClient::DelStaticArp(const std::string &ipAddr, const std::string &macAddr, const std::string &ifName)
{
    NETMGR_LOG_I("DelStaticArp client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->DelStaticArp(ipAddr, macAddr, ifName);
}

int32_t NetConnClient::AddStaticIpv6Addr(const std::string &ipv6Addr, const std::string &macAddr,
    const std::string &ifName)
{
    NETMGR_LOG_I("AddStaticIpv6Addr client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->AddStaticIpv6Addr(ipv6Addr, macAddr, ifName);
}

int32_t NetConnClient::DelStaticIpv6Addr(const std::string &ipv6Addr, const std::string &macAddr,
    const std::string &ifName)
{
    NETMGR_LOG_I("DelStaticIpv6Addr client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->DelStaticIpv6Addr(ipv6Addr, macAddr, ifName);
}

int32_t NetConnClient::RegisterSlotType(uint32_t supplierId, int32_t type)
{
    NETMGR_LOG_I("RegisterSlotType client in.supplierId[%{public}d] type[%{public}d]", supplierId, type);
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->RegisterSlotType(supplierId, type);
}

int32_t NetConnClient::GetSlotType(std::string &type)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->GetSlotType(type);
}

int32_t NetConnClient::FactoryResetNetwork()
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    return proxy->FactoryResetNetwork();
}

int32_t NetConnClient::RegisterNetFactoryResetCallback(const sptr<INetFactoryResetCallback> &callback)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->RegisterNetFactoryResetCallback(callback);
}

int32_t NetConnClient::IsPreferCellularUrl(const std::string& url, bool& preferCellular)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->IsPreferCellularUrl(url, preferCellular);
}

int32_t NetConnClient::RegisterPreAirplaneCallback(const sptr<IPreAirplaneCallback> callback)
{
    NETMGR_LOG_D("RegisterPreAirplaneCallback client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    int32_t ret = proxy->RegisterPreAirplaneCallback(callback);
    if (ret == NETMANAGER_SUCCESS) {
        NETMGR_LOG_D("RegisterPreAirplaneCallback success, save callback.");
        preAirplaneCallback_ = callback;
    }

    return ret;
}

int32_t NetConnClient::UnregisterPreAirplaneCallback(const sptr<IPreAirplaneCallback> callback)
{
    NETMGR_LOG_D("UnregisterPreAirplaneCallback client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }

    int32_t ret = proxy->UnregisterPreAirplaneCallback(callback);
    if (ret == NETMANAGER_SUCCESS) {
        NETMGR_LOG_D("UnregisterPreAirplaneCallback success,delete callback.");
        preAirplaneCallback_ = nullptr;
    }

    return ret;
}

int32_t NetConnClient::UpdateSupplierScore(uint32_t supplierId, uint32_t detectionStatus)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr.");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->UpdateSupplierScore(supplierId, detectionStatus);
}

int32_t NetConnClient::GetDefaultSupplierId(NetBearType bearerType, const std::string &ident,
    uint32_t& supplierId)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr.");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->GetDefaultSupplierId(bearerType, ident, supplierId);
}

std::optional<int32_t> NetConnClient::ObtainTargetApiVersionForSelf()
{
    void *handler = dlopen(LIB_NET_BUNDLE_UTILS_PATH.c_str(), RTLD_LAZY | RTLD_NODELETE);
    if (handler == nullptr) {
        NETMGR_LOG_E("load lib failed, reason : %{public}s", dlerror());
        return std::nullopt;
    }
    using GetNetBundleClass = INetBundle *(*)();
    auto getNetBundle = (GetNetBundleClass)dlsym(handler, "GetNetBundle");
    if (getNetBundle == nullptr) {
        NETMGR_LOG_E("GetNetBundle failed, reason : %{public}s", dlerror());
        dlclose(handler);
        return std::nullopt;
    }
    auto netBundle = getNetBundle();
    if (netBundle == nullptr) {
        NETMGR_LOG_E("netBundle is nullptr");
        dlclose(handler);
        return std::nullopt;
    }
    auto result = netBundle->ObtainTargetApiVersionForSelf();
    dlclose(handler);
    return result;
}

bool NetConnClient::IsAPIVersionSupported(int targetApiVersion)
{
    static auto currentApiVersion = ObtainTargetApiVersionForSelf();
    // Returns true by default in case can not get bundle info from bundle mgr.
    return currentApiVersion.value_or(targetApiVersion) >= targetApiVersion;
}

std::optional<std::string> NetConnClient::ObtainBundleNameForSelf()
{
    static auto bundleName = ObtainBundleNameFromBundleMgr();
    return bundleName;
}

std::optional<std::string> NetConnClient::ObtainBundleNameFromBundleMgr()
{
    void *handler = dlopen(LIB_NET_BUNDLE_UTILS_PATH.c_str(), RTLD_LAZY | RTLD_NODELETE);
    if (handler == nullptr) {
        NETMGR_LOG_E("load lib failed, reason : %{public}s", dlerror());
        return std::nullopt;
    }
    using GetNetBundleClass = INetBundle *(*)();
    auto getNetBundle = (GetNetBundleClass)dlsym(handler, "GetNetBundle");
    if (getNetBundle == nullptr) {
        NETMGR_LOG_E("GetNetBundle failed, reason : %{public}s", dlerror());
        dlclose(handler);
        return std::nullopt;
    }
    auto netBundle = getNetBundle();
    if (netBundle == nullptr) {
        NETMGR_LOG_E("netBundle is nullptr");
        dlclose(handler);
        return std::nullopt;
    }
    auto result = netBundle->ObtainBundleNameForSelf();
    dlclose(handler);
    return result;
}

int32_t NetConnClient::CloseSocketsUid(int32_t netId, uint32_t uid)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->CloseSocketsUid(netId, uid);
}

int32_t NetConnClient::GetSpecificNet(NetBearType bearerType, std::list<int32_t> &netIdList)
{
    sptr<INetConnService> proxy= GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->GetSpecificNet(bearerType, netIdList);
}

int32_t NetConnClient::GetSpecificNetByIdent(NetBearType bearerType, const std::string &ident,
                                             std::list<int32_t> &netIdList)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("GetSpecificNetByIdent proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->GetSpecificNetByIdent(bearerType, ident, netIdList);
}

int32_t NetConnClient::SetAppIsFrozened(uint32_t uid, bool isFrozened)
{
    sptr<INetConnService> proxy= GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->SetAppIsFrozened(uid, isFrozened);
}

int32_t NetConnClient::EnableAppFrozenedCallbackLimitation(bool flag)
{
    sptr<INetConnService> proxy= GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->EnableAppFrozenedCallbackLimitation(flag);
}

int32_t NetConnClient::SetReuseSupplierId(uint32_t supplierId, uint32_t reuseSupplierId, bool isReused)
{
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->SetReuseSupplierId(supplierId, reuseSupplierId, isReused);
}

int32_t NetConnClient::GetNetExtAttribute(const NetHandle &netHandle, std::string &netExtAttribute)
{
    NETMGR_LOG_D("GetNetExtAttribute client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("GetNetExtAttribute proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->GetNetExtAttribute(netHandle.GetNetId(), netExtAttribute);
}

int32_t NetConnClient::SetNetExtAttribute(const NetHandle &netHandle, const std::string &netExtAttribute)
{
    NETMGR_LOG_D("SetNetExtAttribute client in.");
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("GetSpecificNetByIdent proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    return proxy->SetNetExtAttribute(netHandle.GetNetId(), netExtAttribute);
}

int32_t NetConnClient::NetConnCallbackManager::NetAvailable(sptr<NetHandle> &netHandle)
{
    netHandle_ = netHandle;
    std::shared_lock<std::shared_mutex> lock(netConnCallbackListMutex_);
    std::list<sptr<INetConnCallback>> tmpList(netConnCallbackList_);
    lock.unlock();
    for (auto& cb : tmpList) {
        cb->NetAvailable(netHandle);
    }
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::NetConnCallbackManager::NetCapabilitiesChange(sptr<NetHandle> &netHandle,
    const sptr<NetAllCapabilities> &netAllCap)
{
    if (netHandle_ != nullptr && netHandle->GetNetId() == netHandle_->GetNetId()) {
        netAllCap_ = netAllCap;
    }
    std::shared_lock<std::shared_mutex> lock(netConnCallbackListMutex_);
    std::list<sptr<INetConnCallback>> tmpList(netConnCallbackList_);
    lock.unlock();
    for (auto& cb : tmpList) {
        cb->NetCapabilitiesChange(netHandle, netAllCap);
    }
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::NetConnCallbackManager::NetConnectionPropertiesChange(sptr<NetHandle> &netHandle,
    const sptr<NetLinkInfo> &info)
{
    if (netHandle_ != nullptr && netHandle->GetNetId() == netHandle_->GetNetId()) {
        netLinkInfo_ = info;
    }
    std::shared_lock<std::shared_mutex> lock(netConnCallbackListMutex_);
    std::list<sptr<INetConnCallback>> tmpList(netConnCallbackList_);
    lock.unlock();
    for (auto& cb : tmpList) {
        cb->NetConnectionPropertiesChange(netHandle, info);
    }
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::NetConnCallbackManager::NetLost(sptr<NetHandle> &netHandle)
{
    if (netHandle_ != nullptr && netHandle->GetNetId() == netHandle_->GetNetId()) {
        netHandle_ = nullptr;
        netAllCap_ = nullptr;
        netLinkInfo_ = nullptr;
    }
    std::shared_lock<std::shared_mutex> lock(netConnCallbackListMutex_);
    std::list<sptr<INetConnCallback>> tmpList(netConnCallbackList_);
    lock.unlock();
    for (auto& cb : tmpList) {
        cb->NetLost(netHandle);
    }
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::NetConnCallbackManager::NetUnavailable()
{
    netHandle_ = nullptr;
    std::shared_lock<std::shared_mutex> lock(netConnCallbackListMutex_);
    std::list<sptr<INetConnCallback>> tmpList(netConnCallbackList_);
    lock.unlock();
    for (auto& cb : tmpList) {
        cb->NetUnavailable();
    }
    return NETMANAGER_SUCCESS;
}

int32_t NetConnClient::NetConnCallbackManager::NetBlockStatusChange(sptr<NetHandle> &netHandle, bool blocked)
{
    std::shared_lock<std::shared_mutex> lock(netConnCallbackListMutex_);
    std::list<sptr<INetConnCallback>> tmpList(netConnCallbackList_);
    lock.unlock();
    for (auto& cb : tmpList) {
        cb->NetBlockStatusChange(netHandle, blocked);
    }
    return NETMANAGER_SUCCESS;
}

void NetConnClient::NetConnCallbackManager::AddNetConnCallback(const sptr<INetConnCallback>& callback)
{
    std::unique_lock<std::shared_mutex> lock(netConnCallbackListMutex_);
    for (auto& cb : netConnCallbackList_) {
        if (cb == callback) {
            return;
        }
    }
    netConnCallbackList_.push_back(callback);
    lock.unlock();
#ifndef NETMANAGER_TEST
    ffrt::submit([this, callback] () {
#endif
            if (netHandle_ == nullptr) {
                return;
            }
            callback->NetAvailable(netHandle_);
            if (netAllCap_ != nullptr) {
                callback->NetCapabilitiesChange(netHandle_, netAllCap_);
            }
            if (netLinkInfo_ != nullptr) {
                callback->NetConnectionPropertiesChange(netHandle_, netLinkInfo_);
            }
#ifndef NETMANAGER_TEST
        },
        {}, {}, ffrt::task_attr().name("AddNetConnCallback"));
#endif
}

void NetConnClient::NetConnCallbackManager::RemoveNetConnCallback(const sptr<INetConnCallback>& callback)
{
    std::unique_lock<std::shared_mutex> lock(netConnCallbackListMutex_);
    netConnCallbackList_.remove(callback);
}

int32_t NetConnClient::UnRegisterNetConnCallbackManager(const sptr<INetConnCallback>& callback,
    NetConnCallbackManagerMap& netConnCallbackManagerMap)
{
#ifndef NETMANAGER_TEST
    if (!NetManagerPermission::CheckPermission(Permission::GET_NETWORK_INFO)) {
        NETMGR_LOG_I("Permission deny: Request with INTERNAL_DEFAULT But not has CONNECTIVITY_INTERNAL");
        return NETMANAGER_ERR_PERMISSION_DENIED;
    }
#endif
    sptr<INetConnService> proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("The parameter of proxy is nullptr");
        return NETMANAGER_ERR_GET_PROXY_FAIL;
    }
    int ret = NETMANAGER_SUCCESS;
    for (auto itMap = netConnCallbackManagerMap.begin(); itMap != netConnCallbackManagerMap.end();) {
        auto& netConnCallbackManager = itMap->second;
        netConnCallbackManager->netConnCallbackList_.remove(callback);
        if (netConnCallbackManager->netConnCallbackList_.empty()) {
            ret = proxy->UnregisterNetConnCallback(netConnCallbackManager);
            if (ret == NETMANAGER_SUCCESS) {
                NETMGR_LOG_D("UnregisterNetConnCallback success, delete callback.");
                itMap = netConnCallbackManagerMap.erase(itMap);
                continue;
            }
        }
        itMap++;
    }
    return ret;
}

void NetConnClient::RecoverCallbackAndGlobalProxy(NetConnCallbackManagerMap& netConnCallbackManagerMap)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        NETMGR_LOG_E("proxy is nullptr");
        return;
    }
    for (auto& it : netConnCallbackManagerMap) {
        bool isInternalDefault = it.first->netCapabilities_.netCaps_.
            count(NetManagerStandard::NET_CAPABILITY_INTERNAL_DEFAULT) > 0;
        int32_t ret = NETMANAGER_SUCCESS;
        if (isInternalDefault) {
            ret = proxy->RequestNetConnection(it.first, it.second, 0);
        } else {
            ret = proxy->RegisterNetConnCallback(it.first, it.second, 0);
        }
        NETMGR_LOG_D("Register result hasNetSpecifier_ %{public}d", ret);
    }
}
} // namespace NetManagerStandard
} // namespace OHOS

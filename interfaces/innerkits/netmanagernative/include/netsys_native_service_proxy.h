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

#ifndef NETSYS_NATIVE_SERVICE_PROXY_H
#define NETSYS_NATIVE_SERVICE_PROXY_H

#include "i_netsys_service.h"
#include "iremote_proxy.h"

#define NET_SYMBOL_VISIBLE __attribute__ ((visibility("default")))
namespace OHOS {
namespace NetsysNative {
class NET_SYMBOL_VISIBLE NetsysNativeServiceProxy : public IRemoteProxy<INetsysService> {
public:
    explicit NetsysNativeServiceProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<INetsysService>(impl) {}
    ~NetsysNativeServiceProxy() override {}
    bool WriteInterfaceToken(MessageParcel &data);
    int32_t SetResolverConfig(uint16_t netId, uint16_t baseTimeoutMsec, uint8_t retryCount,
                              const std::vector<std::string> &servers,
                              const std::vector<std::string> &domains) override;
    int32_t GetResolverConfig(uint16_t netId, std::vector<std::string> &servers, std::vector<std::string> &domains,
                              uint16_t &baseTimeoutMsec, uint8_t &retryCount) override;
    int32_t CreateNetworkCache(uint16_t netId, bool isVpnNet = false) override;
    int32_t DestroyNetworkCache(uint16_t netId, bool isVpnNet = false) override;
    int32_t GetAddrInfo(const std::string &hostName, const std::string &serverName, const AddrInfo &hints,
                        uint16_t netId, std::vector<AddrInfo> &res) override;
    int32_t SetInterfaceMtu(const std::string &interfaceName, int32_t mtu) override;
    int32_t GetInterfaceMtu(const std::string &interfaceName) override;

    int32_t SetTcpBufferSizes(const std::string &tcpBufferSizes) override;

    int32_t RegisterNotifyCallback(sptr<INotifyCallback> &callback) override;
    int32_t UnRegisterNotifyCallback(sptr<INotifyCallback> &callback) override;

    int32_t NetworkAddRoute(int32_t netId, const std::string &interfaceName, const std::string &destination,
                            const std::string &nextHop, bool isExcludedRoute = false) override;
    int32_t NetworkRemoveRoute(int32_t netId, const std::string &interfaceName, const std::string &destination,
                               const std::string &nextHop) override;
    int32_t NetworkAddRouteParcel(int32_t netId, const RouteInfoParcel &routeInfo) override;
    int32_t NetworkRemoveRouteParcel(int32_t netId, const RouteInfoParcel &routeInfo) override;
    int32_t NetworkSetDefault(int32_t netId) override;
    int32_t NetworkGetDefault() override;
    int32_t NetworkClearDefault() override;
    int32_t GetProcSysNet(int32_t family, int32_t which, const std::string &ifname, const std::string &parameter,
                          std::string &value) override;
    int32_t SetProcSysNet(int32_t family, int32_t which, const std::string &ifname, const std::string &parameter,
                          std::string &value) override;
    int32_t SetInternetPermission(uint32_t uid, uint8_t allow, uint8_t isBroker) override;
    int32_t NetworkCreatePhysical(int32_t netId, int32_t permission) override;
    int32_t NetworkCreateVirtual(int32_t netId, bool hasDns) override;
    int32_t NetworkAddUids(int32_t netId, const std::vector<UidRange> &uidRanges) override;
    int32_t NetworkDelUids(int32_t netId, const std::vector<UidRange> &uidRanges) override;
    int32_t AddInterfaceAddress(const std::string &interfaceName, const std::string &addrString,
                                int32_t prefixLength) override;
    int32_t DelInterfaceAddress(const std::string &interfaceName, const std::string &addrString,
                                int32_t prefixLength) override;
    int32_t DelInterfaceAddress(const std::string &interfaceName, const std::string &addrString,
                                int32_t prefixLength, const std::string &netCapabilities) override;
    int32_t InterfaceSetIpAddress(const std::string &ifaceName, const std::string &ipAddress) override;
    int32_t InterfaceSetIffUp(const std::string &ifaceName) override;
    int32_t NetworkAddInterface(int32_t netId, const std::string &iface, NetBearType netBearerType) override;
    int32_t NetworkRemoveInterface(int32_t netId, const std::string &iface) override;
    int32_t NetworkDestroy(int32_t netId, bool isVpnNet = false) override;
    int32_t CreateVnic(uint16_t mtu, const std::string &tunAddr, int32_t prefix,
                       const std::set<int32_t> &uids) override;
    int32_t DestroyVnic() override;
    int32_t EnableDistributedClientNet(const std::string &virnicAddr, const std::string &iif) override;
    int32_t EnableDistributedServerNet(const std::string &iif, const std::string &devIface,
                                       const std::string &dstAddr) override;
    int32_t DisableDistributedNet(bool isServer) override;
    int32_t GetFwmarkForNetwork(int32_t netId, MarkMaskParcel &markMaskParcel) override;
    int32_t SetInterfaceConfig(const InterfaceConfigurationParcel &cfg) override;
    int32_t GetInterfaceConfig(InterfaceConfigurationParcel &cfg) override;
    int32_t StartDhcpClient(const std::string &iface, bool bIpv6) override;
    int32_t InterfaceGetList(std::vector<std::string> &ifaces) override;
    int32_t StopDhcpClient(const std::string &iface, bool bIpv6) override;
    int32_t StartDhcpService(const std::string &iface, const std::string &ipv4addr) override;
    int32_t StopDhcpService(const std::string &iface) override;
    int32_t IpEnableForwarding(const std::string &requestor) override;
    int32_t IpDisableForwarding(const std::string &requestor) override;
    int32_t EnableNat(const std::string &downstreamIface, const std::string &upstreamIface) override;
    int32_t DisableNat(const std::string &downstreamIface, const std::string &upstreamIface) override;
    int32_t IpfwdAddInterfaceForward(const std::string &fromIface, const std::string &toIface) override;
    int32_t IpfwdRemoveInterfaceForward(const std::string &fromIface, const std::string &toIface) override;
    int32_t FirewallEnableChain(uint32_t chain, bool enable) override;
    int32_t FirewallSetUidRule(uint32_t chain, const std::vector<uint32_t> &uids, uint32_t firewallRule) override;
    int32_t BandwidthRemoveAllowedList(uint32_t uid) override;
    int32_t FirewallSetUidsAllowedListChain(uint32_t chain, const std::vector<uint32_t> &uids) override;
    int32_t FirewallSetUidsDeniedListChain(uint32_t chain, const std::vector<uint32_t> &uids) override;
    int32_t BandwidthRemoveIfaceQuota(const std::string &ifName) override;
    int32_t BandwidthRemoveDeniedList(uint32_t uid) override;
    int32_t BandwidthAddDeniedList(uint32_t uid) override;
    int32_t BandwidthAddAllowedList(uint32_t uid) override;
    int32_t BandwidthEnableDataSaver(bool enable) override;
    int32_t BandwidthSetIfaceQuota(const std::string &ifName, int64_t bytes) override;
    int32_t ShareDnsSet(uint16_t netId) override;
    int32_t StartDnsProxyListen() override;
    int32_t StopDnsProxyListen() override;
    int32_t GetNetworkSharingTraffic(const std::string &downIface, const std::string &upIface,
                                     NetworkSharingTraffic &traffic) override;
    int32_t GetNetworkCellularSharingTraffic(NetworkSharingTraffic &traffic, std::string &ifaceName) override;
    int32_t GetTotalStats(uint64_t &stats, uint32_t type) override;
    int32_t GetUidStats(uint64_t &stats, uint32_t type, uint32_t uid) override;
    int32_t GetIfaceStats(uint64_t &stats, uint32_t type, const std::string &interfaceName) override;
    int32_t GetAllStatsInfo(std::vector<OHOS::NetManagerStandard::NetStatsInfo> &stats) override;
    int32_t DeleteStatsInfo(uint32_t uid) override;
    int32_t GetAllSimStatsInfo(std::vector<OHOS::NetManagerStandard::NetStatsInfo> &stats) override;
    int32_t DeleteSimStatsInfo(uint32_t uid) override;
    int32_t SetNetStateTrafficMap(uint8_t flag, uint64_t availableTraffic) override;
    int32_t SetNetStatusMap(uint8_t type, uint8_t value) override;
    int32_t GetNetStateTrafficMap(uint8_t flag, uint64_t &availableTraffic) override;
    int32_t ClearIncreaseTrafficMap() override;
    int32_t DeleteIncreaseTrafficMap(uint64_t ifIndex) override;
    int32_t UpdateIfIndexMap(int8_t key, uint64_t index) override;
    int32_t SetIptablesCommandForRes(const std::string &cmd, std::string &respond, IptablesType ipType) override;
    int32_t SetIpCommandForRes(const std::string &cmd, std::string &respond) override;
    int32_t NetDiagPingHost(const NetDiagPingOption &pingOption, const sptr<INetDiagCallback> &callback) override;
    int32_t NetDiagGetRouteTable(std::list<NetDiagRouteTable> &routeTables) override;
    int32_t NetDiagGetSocketsInfo(NetDiagProtocolType socketType, NetDiagSocketsInfo &socketsInfo) override;
    int32_t NetDiagGetInterfaceConfig(std::list<NetDiagIfaceConfig> &configs, const std::string &ifaceName) override;
    int32_t NetDiagUpdateInterfaceConfig(const NetDiagIfaceConfig &config, const std::string &ifaceName,
                                         bool add) override;
    int32_t NetDiagSetInterfaceActiveState(const std::string &ifaceName, bool up) override;
    int32_t AddStaticArp(const std::string &ipAddr, const std::string &macAddr,
                         const std::string &ifName) override;
    int32_t DelStaticArp(const std::string &ipAddr, const std::string &macAddr,
                         const std::string &ifName) override;

    int32_t RegisterDnsResultCallback(const sptr<INetDnsResultCallback> &callback, uint32_t delay) override;
    int32_t UnregisterDnsResultCallback(const sptr<INetDnsResultCallback> &callback) override;
    int32_t RegisterDnsHealthCallback(const sptr<INetDnsHealthCallback> &callback) override;
    int32_t UnregisterDnsHealthCallback(const sptr<INetDnsHealthCallback> &callback) override;
    int32_t GetCookieStats(uint64_t &stats, uint32_t type, uint64_t cookie) override;
    int32_t GetNetworkSharingType(std::set<uint32_t>& sharingTypeIsOn)  override;
    int32_t UpdateNetworkSharingType(uint32_t type, bool isOpen) override;
#ifdef FEATURE_NET_FIREWALL_ENABLE
    int32_t SetFirewallRules(NetFirewallRuleType type, const std::vector<sptr<NetFirewallBaseRule>> &ruleList,
                             bool isFinish) override;
    int32_t SetFirewallDefaultAction(int32_t userId, FirewallRuleAction inDefault,
                                     FirewallRuleAction outDefault) override;
    int32_t SetFirewallCurrentUserId(int32_t userId) override;
    int32_t ClearFirewallRules(NetFirewallRuleType type) override;
    int32_t RegisterNetFirewallCallback(const sptr<INetFirewallCallback> &callback) override;
    int32_t UnRegisterNetFirewallCallback(const sptr<INetFirewallCallback> &callback) override;
#endif
#ifdef FEATURE_WEARABLE_DISTRIBUTED_NET_ENABLE
    int32_t EnableWearableDistributedNetForward(const int32_t tcpPortId, const int32_t udpPortId) override;
    int32_t DisableWearableDistributedNetForward() override;
#endif
    int32_t SetNetworkAccessPolicy(uint32_t uid, NetworkAccessPolicy policy, bool reconfirmFlag) override;
    int32_t DeleteNetworkAccessPolicy(uint32_t uid) override;
    int32_t NotifyNetBearerTypeChange(std::set<NetBearType> bearerTypes) override;

    int32_t SetIpv6PrivacyExtensions(const std::string &interfaceName, const uint32_t on) override;
    int32_t SetEnableIpv6(const std::string &interfaceName, const uint32_t on) override;
    int32_t StartClat(const std::string &interfaceName, int32_t netId, const std::string &nat64PrefixStr) override;
    int32_t StopClat(const std::string &interfaceName) override;
    int32_t ClearFirewallAllRules() override;
    int32_t SetNicTrafficAllowed(const std::vector<std::string> &ifaceNames, bool status) override;
    int32_t CloseSocketsUid(const std::string &ipAddr, uint32_t uid) override;
#ifdef SUPPORT_SYSVPN
    int32_t ProcessVpnStage(NetsysNative::SysVpnStageCode stage, const std::string &message = "") override;
    int32_t UpdateVpnRules(uint16_t netId, const std::vector<std::string> &extMessages, bool add) override;
#endif // SUPPORT_SYSVPN
    int32_t SetBrokerUidAccessPolicyMap(const std::unordered_map<uint32_t, uint32_t> &uidMaps) override;
    int32_t DelBrokerUidAccessPolicyMap(uint32_t uid) override;
    int32_t SetUserDefinedServerFlag(uint16_t netId, bool isUserDefinedServer) override;
    int32_t RegisterNetsysTrafficCallback(const sptr<INetsysTrafficCallback> &callback) override;
    int32_t UnRegisterNetsysTrafficCallback(const sptr<INetsysTrafficCallback> &callback) override;
    int32_t FlushDnsCache(uint16_t netId) override;
    int32_t SetDnsCache(uint16_t netId, const std::string &hostName, const AddrInfo &addrInfo) override;
    int32_t AddStaticIpv6Addr(const std::string &ipv6Addr, const std::string &macAddr,
        const std::string &ifName) override;
    int32_t DelStaticIpv6Addr(const std::string &ipv6Addr, const std::string &macAddr,
        const std::string &ifName) override;
#ifdef FEATURE_ENTERPRISE_ROUTE_CUSTOM
    int32_t UpdateEnterpriseRoute(const std::string &interfaceName, uint32_t uid, bool add) override;
#endif

private:
    int32_t DealBandwidth(uint32_t uid, uint32_t code);
    static inline BrokerDelegator<NetsysNativeServiceProxy> delegator_;
};
} // namespace NetsysNative
} // namespace OHOS
#endif // NETSYS_NATIVE_SERVICE_PROXY_H

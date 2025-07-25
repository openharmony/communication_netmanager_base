/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "multi_vpn_manager.h"

#include <sys/ioctl.h>
#include <thread>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include <linux/if_tun.h>
#include "init_socket.h"
#include "net_manager_constants.h"
#include "netmanager_base_common_utils.h"
#include "netnative_log_wrapper.h"
#include "securec.h"
#include "netlink_socket.h"
#include "route_manager.h"

namespace OHOS {
namespace NetManagerStandard {

namespace {
constexpr uint32_t DEFAULT_MTU = 1500;
constexpr int32_t NET_MASK_MAX_LENGTH = 32;
constexpr int32_t MAX_UNIX_SOCKET_CLIENT = 5;
} // namespace

int32_t MultiVpnManager::SendVpnInterfaceFdToClient(int32_t clientFd, int32_t tunFd)
{
    char buf[1] = {0};
    iovec iov;
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    union {
        cmsghdr align;
        char cmsg[CMSG_SPACE(sizeof(int32_t))];
    } cmsgu;
    if (memset_s(cmsgu.cmsg, sizeof(cmsgu.cmsg), 0, sizeof(cmsgu.cmsg)) != EOK) {
        NETNATIVE_LOGE("memset_s cmsgu.cmsg failed!");
        return NETMANAGER_ERROR;
    }
    msghdr message;
    if (memset_s(&message, sizeof(message), 0, sizeof(message)) != EOK) {
        NETNATIVE_LOGE("memset_s message failed!");
        return NETMANAGER_ERROR;
    }

    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = cmsgu.cmsg;
    message.msg_controllen = sizeof(cmsgu.cmsg);
    cmsghdr *cmsgh = CMSG_FIRSTHDR(&message);
    cmsgh->cmsg_len = CMSG_LEN(sizeof(tunFd));
    cmsgh->cmsg_level = SOL_SOCKET;
    cmsgh->cmsg_type = SCM_RIGHTS;
    if (memcpy_s(CMSG_DATA(cmsgh), sizeof(tunFd), &tunFd, sizeof(tunFd)) != EOK) {
        NETNATIVE_LOGE("memcpy_s cmsgu failed!");
        return NETMANAGER_ERROR;
    }
    if (sendmsg(clientFd, &message, 0) < 0) {
        NETNATIVE_LOGE("sendmsg error: %{public}d, clientfd[%{public}d], tunfd[%{public}d]", errno, clientFd, tunFd);
        return NETMANAGER_ERROR;
    }
    return NETMANAGER_SUCCESS;
}

int32_t MultiVpnManager::InitIfreq(ifreq &ifr, const std::string &ifName)
{
    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK) {
        NETNATIVE_LOGE("memset_s ifr failed!");
        return NETMANAGER_ERROR;
    }
    if (strncpy_s(ifr.ifr_name, IFNAMSIZ, ifName.c_str(), strlen(ifName.c_str())) != EOK) {
        NETNATIVE_LOGE("strcpy_s ifr name fail");
        return NETMANAGER_ERROR;
    }
    return NETMANAGER_SUCCESS;
}

int32_t MultiVpnManager::SetVpnResult(std::atomic_int &fd, unsigned long cmd, ifreq &ifr)
{
    if (fd > 0) {
        if (ioctl(fd, cmd, &ifr) < 0) {
            NETNATIVE_LOGE("set vpn error, errno:%{public}d", errno);
            return NETMANAGER_ERROR;
        }
    }
    return NETMANAGER_SUCCESS;
}

int32_t MultiVpnManager::SetVpnMtu(const std::string &ifName, int32_t mtu)
{
    if (mtu <= 0) {
        NETNATIVE_LOGE("invalid mtu value");
        return NETMANAGER_ERROR;
    }

    ifreq ifr;
    if (InitIfreq(ifr, ifName) != NETMANAGER_SUCCESS) {
        return NETMANAGER_ERROR;
    }
    ifr.ifr_mtu = mtu;

    std::atomic_int net4Sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (net4Sock < 0) {
        NETNATIVE_LOGE("create SOCK_DGRAM ipv4 failed: %{public}d", errno);
        return NETMANAGER_ERROR;
    }
    int32_t ret4 = SetVpnResult(net4Sock, SIOCSIFMTU, ifr);
    close(net4Sock);
    if (ret4 == NETMANAGER_ERROR) {
        NETNATIVE_LOGI("set MTU failed");
        return NETMANAGER_ERROR;
    }
    return NETMANAGER_SUCCESS;
}

int32_t MultiVpnManager::AddVpnRemoteAddress(const std::string &ifName, std::atomic_int &net4Sock, ifreq &ifr)
{
    /* ppp need set dst ip */
    if (strstr(ifName.c_str(), PPP_CARD_NAME) != NULL) {
        in_addr remoteIpv4Addr = {};
        if (inet_aton(remoteIpv4Addr_.c_str(), &remoteIpv4Addr) == 0) {
            NETNATIVE_LOGE("addr inet_aton error");
            return NETMANAGER_ERROR;
        }
        auto remoteAddr = reinterpret_cast<sockaddr_in *>(&ifr.ifr_dstaddr);
        remoteAddr->sin_family = AF_INET;
        remoteAddr->sin_addr = remoteIpv4Addr;
        if (ioctl(net4Sock, SIOCSIFDSTADDR, &ifr) < 0) {
            NETNATIVE_LOGE("ioctl set ipv4 address failed: %{public}d", errno);
            return NETMANAGER_ERROR;
        }
    }
    return NETMANAGER_SUCCESS;
}

int32_t MultiVpnManager::SetVpnAddress(const std::string &ifName, const std::string &vpnAddr, int32_t prefix)
{
    ifreq ifr = {};
    if (InitIfreq(ifr, ifName) != NETMANAGER_SUCCESS) {
        return NETMANAGER_ERROR;
    }
    std::atomic_int net4Sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (net4Sock < 0) {
        NETNATIVE_LOGE("create SOCK_DGRAM ipv4 failed: %{public}d", errno);
        return NETMANAGER_ERROR;
    }
    in_addr ipv4Addr = {};
    if (inet_aton(vpnAddr.c_str(), &ipv4Addr) == 0) {
        NETNATIVE_LOGE("addr inet_aton error");
        close(net4Sock);
        return NETMANAGER_ERROR;
    }

    auto sin = reinterpret_cast<sockaddr_in *>(&ifr.ifr_addr);
    sin->sin_family = AF_INET;
    sin->sin_addr = ipv4Addr;
    if (ioctl(net4Sock, SIOCSIFADDR, &ifr) < 0) {
        NETNATIVE_LOGE("ioctl set ipv4 address failed: %{public}d", errno);
        close(net4Sock);
        return NETMANAGER_ERROR;
    }
    /* ppp need set dst ip */
    if (AddVpnRemoteAddress(ifName, net4Sock, ifr) != NETMANAGER_SUCCESS) {
        close(net4Sock);
        return NETMANAGER_ERROR;
    }
    if (prefix <= 0 || prefix > NET_MASK_MAX_LENGTH) {
        NETNATIVE_LOGE("prefix: %{public}d error", prefix);
        close(net4Sock);
        return NETMANAGER_ERROR;
    }
    in_addr_t mask = prefix ? (~0 << (NET_MASK_MAX_LENGTH - prefix)) : 0;
    sin = reinterpret_cast<sockaddr_in *>(&ifr.ifr_netmask);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(mask);
    if (ioctl(net4Sock, SIOCSIFNETMASK, &ifr) < 0) {
        NETNATIVE_LOGE("ioctl set ip mask failed: %{public}d", errno);
        close(net4Sock);
        return NETMANAGER_ERROR;
    }

    SetVpnUp(ifName);
    close(net4Sock);
    NETNATIVE_LOGI("set ip address success");
    return NETMANAGER_SUCCESS;
}

int32_t MultiVpnManager::SetVpnUp(const std::string &ifName)
{
    ifreq ifr = {};
    if (InitIfreq(ifr, ifName) != NETMANAGER_SUCCESS) {
        return NETMANAGER_ERROR;
    }
    ifr.ifr_flags = IFF_UP | IFF_NOARP;
    std::atomic_int net4Sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (net4Sock < 0) {
        NETNATIVE_LOGE("create SOCK_DGRAM ipv4 failed: %{public}d", errno);
        return NETMANAGER_ERROR;
    }
    int32_t ret4 = SetVpnResult(net4Sock, SIOCSIFFLAGS, ifr);
    close(net4Sock);
    if (ret4 == NETMANAGER_ERROR) {
        NETNATIVE_LOGI("set iff up failed");
        return NETMANAGER_ERROR;
    }
    return NETMANAGER_SUCCESS;
}

int32_t MultiVpnManager::SetVpnDown(const std::string &ifName)
{
    ifreq ifr = {};
    if (InitIfreq(ifr, ifName) != NETMANAGER_SUCCESS) {
        return NETMANAGER_ERROR;
    }
    ifr.ifr_flags &= ~IFF_UP;
    std::atomic_int net4Sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (net4Sock < 0) {
        NETNATIVE_LOGE("create SOCK_DGRAM ipv4 failed: %{public}d", errno);
        return NETMANAGER_ERROR;
    }
    int32_t ret4 = SetVpnResult(net4Sock, SIOCSIFFLAGS, ifr);
    close(net4Sock);
    if (ret4 == NETMANAGER_ERROR) {
        NETNATIVE_LOGI("set iff down failed");
        return NETMANAGER_ERROR;
    }
    return NETMANAGER_SUCCESS;
}

int32_t MultiVpnManager::CreateVpnInterface(const std::string &ifName)
{
    int32_t ret = NETMANAGER_SUCCESS;
    if (strstr(ifName.c_str(), XFRM_CARD_NAME) != NULL) {
        uint32_t ifNameId = CommonUtils::StrToUint(ifName.substr(strlen(XFRM_CARD_NAME)));
        ret = nmd::CreateVpnIfByNetlink(ifName.c_str(), ifNameId, phyName_.c_str(), DEFAULT_MTU);
    } else if (strstr(ifName.c_str(), PPP_CARD_NAME) != NULL) {
        ret = CreatePppInterface(ifName);
    } else if (strstr(ifName.c_str(), MULTI_TUN_CARD_NAME) != NULL) {
        ret = CreateMultiTunInterface(ifName);
    } else {
        NETNATIVE_LOGE("CreateVpnInterface failed, invalid ifName");
        return NETMANAGER_ERROR;
    }
    return ret;
}

int32_t MultiVpnManager::DestroyVpnInterface(const std::string &ifName)
{
    NETNATIVE_LOGI("destroy vpn interface:%{public}s", ifName.c_str());
    bool isXfrm = strstr(ifName.c_str(), XFRM_CARD_NAME) != NULL;
    bool isPpp = strstr(ifName.c_str(), PPP_CARD_NAME) != NULL;
    bool isMultiTun = strstr(ifName.c_str(), MULTI_TUN_CARD_NAME) != NULL;
    if (!isXfrm && !isPpp && !isMultiTun) {
        NETNATIVE_LOGE("DestroyVpnInterface failed, invalid ifName");
        return NETMANAGER_ERROR;
    }
    SetVpnDown(ifName);
    nmd::DeleteVpnIfByNetlink(ifName.c_str());
    if (isPpp || isMultiTun) {
        DestroyMultiVpnFd(ifName);
    }
    return NETMANAGER_SUCCESS;
}

int32_t MultiVpnManager::CreatePppInterface(const std::string &ifName)
{
    auto it = multiVpnFdMap_.find(ifName);
    if (it == multiVpnFdMap_.end()) {
        NETNATIVE_LOGE("ifName not exist");
        return NETMANAGER_ERROR;
    }
    ifreq ifr = {};
    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK) {
        NETNATIVE_LOGE("memset_s ifr failed!");
        return NETMANAGER_ERROR;
    }
    int32_t currentIfunit = 0;
    if (ioctl(multiVpnFdMap_[ifName], PPPIOCGUNIT, &currentIfunit) < 0) {
        NETNATIVE_LOGE("ioctl PPPIOCDISCONN failed errno: %{public}d", errno);
    }
    NETNATIVE_LOGI("Created PPP interface: currentIfunit:%{public}d\n", currentIfunit);
    std::string oldName = "ppp" + std::to_string(currentIfunit);
    SetVpnDown(oldName);
    if (strncpy_s(ifr.ifr_name, IFNAMSIZ, oldName.c_str(), strlen(oldName.c_str())) != EOK) {
        NETNATIVE_LOGE("strcpy_s ifr name fail");
        return NETMANAGER_ERROR;
    }
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (strncpy_s(ifr.ifr_newname, IFNAMSIZ, ifName.c_str(), strlen(ifName.c_str())) != EOK) {
        NETNATIVE_LOGE("strcpy_s ifr name fail");
        return NETMANAGER_ERROR;
    }
    ifr.ifr_newname[IFNAMSIZ - 1] = '\0';
    std::atomic_int net4Sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (net4Sock < 0) {
        NETNATIVE_LOGE("create SOCK_DGRAM ipv4 failed: %{public}d", errno);
        return NETMANAGER_ERROR;
    }
    int32_t ioRet = ioctl(net4Sock, SIOCSIFNAME, &ifr);
    close(net4Sock);
    if (ioRet < 0) {
        NETNATIVE_LOGE("ioctl failed errno: %{public}d", errno);
        return NETMANAGER_ERROR;
    }
    NETNATIVE_LOGI("Created PPP interface");
    return NETMANAGER_SUCCESS;
}

void MultiVpnManager::CreatePppFd(const std::string &ifName)
{
    if (strstr(ifName.c_str(), PPP_CARD_NAME) == NULL) {
        NETNATIVE_LOGE("CreatePppFd failed");
        return;
    }
    multiVpnListeningName_ = ifName;
    StartMultiVpnInterfaceFdListen();
}

int32_t MultiVpnManager::CreateMultiTunInterface(const std::string &ifName)
{
    int32_t multiVpnFd = 0;
    if (GetMultiVpnFd(ifName, multiVpnFd) != NETMANAGER_SUCCESS) {
        return NETMANAGER_ERROR;
    }

    ifreq ifr = {};
    if (InitIfreq(ifr, ifName) != NETMANAGER_SUCCESS) {
        return NETMANAGER_ERROR;
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(multiVpnFd, TUNSETIFF, &ifr) < 0) {
        NETNATIVE_LOGE("multi tun set iff error: %{public}d", errno);
        return NETMANAGER_ERROR;
    }
    multiVpnListeningName_ = ifName;
    StartMultiVpnInterfaceFdListen();
    return NETMANAGER_SUCCESS;
}

int32_t MultiVpnManager::GetMultiVpnFd(const std::string &ifName, int32_t &multiVpnFd)
{
    std::lock_guard<std::mutex> autoLock(mutex_);
    auto it = multiVpnFdMap_.find(ifName);
    if (it != multiVpnFdMap_.end()) {
        NETNATIVE_LOGE("ifName already exist");
        multiVpnFd = it->second.load();
        return NETMANAGER_SUCCESS;
    }
    if (strstr(ifName.c_str(), PPP_CARD_NAME) != NULL) {
        multiVpnFd = open(PPP_DEVICE_PATH, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    } else if (strstr(ifName.c_str(), MULTI_TUN_CARD_NAME) != NULL) {
        multiVpnFd = open(TUN_DEVICE_PATH, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    } else {
        NETNATIVE_LOGE("GetMultiVpnFd faild, IfName err");
        return NETMANAGER_ERROR;
    }
    if (multiVpnFd <= 0) {
        NETNATIVE_LOGE("open virtual device failed: %{public}d", errno);
        return NETMANAGER_ERROR;
    }
    multiVpnFdMap_[ifName] = multiVpnFd;
    return NETMANAGER_SUCCESS;
}

void MultiVpnManager::SetVpnRemoteAddress(const std::string &remoteIp)
{
    remoteIpv4Addr_ = remoteIp;
}

int32_t MultiVpnManager::DestroyMultiVpnFd(const std::string &ifName)
{
    std::lock_guard<std::mutex> autoLock(mutex_);
    if (strstr(ifName.c_str(), PPP_CARD_NAME) == NULL && strstr(ifName.c_str(), MULTI_TUN_CARD_NAME) == NULL) {
        NETNATIVE_LOGE("DestroyMultiVpnFd faild, IfName err");
        return NETMANAGER_ERROR;
    }
    auto it = multiVpnFdMap_.find(ifName);
    if (it == multiVpnFdMap_.end()) {
        NETNATIVE_LOGE("ifName not exist");
        return NETMANAGER_ERROR;
    }
    auto multiVpnFd = it->second.load();
    if (multiVpnFd != 0) {
        close(multiVpnFd);
    }
    multiVpnFdMap_.erase(it);
    return NETMANAGER_SUCCESS;
}

void MultiVpnManager::StartMultiVpnInterfaceFdListen()
{
    if (multiVpnListeningFlag_) {
        NETNATIVE_LOGI("MultiVpnInterface fd is listening...");
        return;
    }
    NETNATIVE_LOGI("StartMultiVpnInterfaceFdListen...");
    multiVpnListeningFlag_ = true;
    std::thread t([sp = shared_from_this()]() { sp->StartMultiVpnSocketListen(); });
    t.detach();
    pthread_setname_np(t.native_handle(), "unix_socket_multivpnfd");
}

void MultiVpnManager::StartMultiVpnSocketListen()
{
    NETNATIVE_LOGI("StartMultiVpnSocketListen...");
    int32_t serverfd = GetControlSocket("multivpnfd");
    if (listen(serverfd, MAX_UNIX_SOCKET_CLIENT) < 0) {
        multiVpnListeningFlag_ = false;
        NETNATIVE_LOGE("listen socket error: %{public}d", errno);
        return;
    }

    sockaddr_in clientAddr;
    socklen_t len = sizeof(clientAddr);
    int32_t clientFd = accept(serverfd, reinterpret_cast<sockaddr *>(&clientAddr), &len);
    if (clientFd < 0) {
        NETNATIVE_LOGE("accept socket error: %{public}d", errno);
        multiVpnListeningFlag_ = false;
        return;
    }
    int32_t multiVpnFd = -1;
    if (GetMultiVpnFd(multiVpnListeningName_, multiVpnFd) == NETMANAGER_SUCCESS) {
        SendVpnInterfaceFdToClient(clientFd, multiVpnFd);
    }
    multiVpnListeningFlag_ = false;
    close(clientFd);
}

void MultiVpnManager::SetXfrmPhyIfName(const std::string &phyName)
{
    phyName_ = phyName;
}

int32_t MultiVpnManager::SetVpnCallMode(const std::string &message)
{
    if (message.empty()) {
        NETNATIVE_LOGE("message is empty");
        return NETMANAGER_ERROR;
    }
    return nmd::RouteManager::SetVpnCallMode(message);
}
} // namespace NetManagerStandard
} // namespace OHOS

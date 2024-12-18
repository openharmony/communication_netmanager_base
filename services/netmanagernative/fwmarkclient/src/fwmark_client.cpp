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

#include "fwmark_client.h"

#include <cerrno>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "fwmark.h"
#include "fwmark_command.h"
#include "net_manager_constants.h"
#include "netnative_log_wrapper.h"
#include "securec.h"

namespace OHOS {
namespace nmd {
using namespace NetManagerStandard;
static constexpr const int32_t ERROR_CODE_SOCKETFD_INVALID = -1;
static constexpr const int32_t ERROR_CODE_CONNECT_FAILED = -2;
static constexpr const int32_t ERROR_CODE_SENDMSG_FAILED = -3;
static constexpr const int32_t ERROR_CODE_READ_FAILED = -4;

FwmarkClient::FwmarkClient() {}

FwmarkClient::~FwmarkClient() {}

int32_t FwmarkClient::BindSocket(int32_t fd, uint32_t netId)
{
    FwmarkCommand command = {FwmarkCommand::SELECT_NETWORK, netId};
    return Send(&command, fd);
}

int32_t FwmarkClient::ProtectFromVpn(int32_t socketFd)
{
    if (socketFd < 0) {
        return HandleError(-1, ERROR_CODE_SOCKETFD_INVALID, socketFd);
    }
    FwmarkCommand command = {FwmarkCommand::PROTECT_FROM_VPN, 0};
    return Send(&command, socketFd);
}

int32_t FwmarkClient::Send(FwmarkCommand *data, int32_t fd)
{
    auto socketFd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socketFd == -1) {
        return HandleError(-1, ERROR_CODE_SOCKETFD_INVALID, socketFd);
    }
    if (connect(socketFd, reinterpret_cast<const sockaddr *>(&FWMARK_SERVER_PATH), sizeof(FWMARK_SERVER_PATH)) == -1) {
        return HandleError(-1, ERROR_CODE_CONNECT_FAILED, socketFd);
    }

    iovec iov;
    iov.iov_base = data;
    iov.iov_len = sizeof(*data);
    msghdr message;
    (void)memset_s(&message, sizeof(message), 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    union {
        cmsghdr cmh;
        char cmsg[CMSG_SPACE(sizeof(fd))];
    } cmsgu;

    (void)memset_s(cmsgu.cmsg, sizeof(cmsgu.cmsg), 0, sizeof(cmsgu.cmsg));
    message.msg_control = cmsgu.cmsg;
    message.msg_controllen = sizeof(cmsgu.cmsg);
    cmsghdr *const cmsgh = CMSG_FIRSTHDR(&message);
    cmsgh->cmsg_len = CMSG_LEN(sizeof(fd));
    cmsgh->cmsg_level = SOL_SOCKET;
    cmsgh->cmsg_type = SCM_RIGHTS;
    (void)memcpy_s(CMSG_DATA(cmsgh), sizeof(fd), &fd, sizeof(fd));
    int32_t ret = sendmsg(socketFd, &message, 0);
    if (ret < 0) {
        return HandleError(ret, ERROR_CODE_SENDMSG_FAILED, socketFd);
    }
    int32_t error = 0;
    ret = read(socketFd, &error, sizeof(error));
    if (ret < 0) {
        return HandleError(ret, ERROR_CODE_READ_FAILED, socketFd);
    }

    close(socketFd);
    return NETMANAGER_SUCCESS;
}

int32_t FwmarkClient::HandleError(int32_t ret, int32_t errorCode, int32_t sock)
{
    switch (errorCode) {
        case ERROR_CODE_SOCKETFD_INVALID:
            NETNATIVE_LOGE("socketFd invalid, ret:%{public}d, errno: %{public}d", ret, errno);
            break;
        case ERROR_CODE_CONNECT_FAILED:
            NETNATIVE_LOGE("connect failed, ret:%{public}d, errno: %{public}d", ret, errno);
            break;
        case ERROR_CODE_SENDMSG_FAILED:
            NETNATIVE_LOGE("sendmsg failed, ret:%{public}d, errno: %{public}d", ret, errno);
            break;
        case ERROR_CODE_READ_FAILED:
            NETNATIVE_LOGE("read failed, ret:%{public}d, errno: %{public}d", ret, errno);
            break;
        default:
            break;
    }
    if (sock > 0) {
        close(sock);
    }
    return NETMANAGER_ERROR;
}

#ifdef __cplusplus
extern int32_t BindSocket(int32_t fd, uint32_t netId)
{
    FwmarkClient instance;
    return instance.BindSocket(fd, netId);
}
#endif
} // namespace nmd
} // namespace OHOS

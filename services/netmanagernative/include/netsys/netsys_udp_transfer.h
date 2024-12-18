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

#ifndef INCLUDE_NETSYS_UDP_CLIENT_H
#define INCLUDE_NETSYS_UDP_CLIENT_H

#include "dns_config_client.h"
#include <iostream>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

namespace OHOS {
namespace nmd {
namespace PollUdpDataTransfer {
int32_t PollUdpSendData(int32_t sock, char *data, size_t size, AlignedSockAddr &addr, socklen_t &lenAddr);
int32_t PollUdpRecvData(int32_t sock, char *data, size_t size, AlignedSockAddr &addr, socklen_t &lenAddr);
bool MakeUdpNonBlock(int32_t sock);
} // namespace PollUdpDataTransfer
} // namespace nmd
} // namespace OHOS
#endif // INCLUDE_NETSYS_UDP_CLIENT_H

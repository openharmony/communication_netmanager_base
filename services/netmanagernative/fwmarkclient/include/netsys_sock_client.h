/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef NETSYS_SOCK_CLIENT_H
#define NETSYS_SOCK_CLIENT_H

#include "app_net_client.h"
#include "musl_socket_dispatch.h"

#ifdef __cplusplus
extern "C" {
#endif

bool ohos_socket_hook_initialize(const SocketDispatchType*, bool*, const char*);
void ohos_socket_hook_finalize(void);
bool ohos_socket_hook_get_hook_flag(void);
bool ohos_socket_hook_set_hook_flag(bool);
int ohos_socket_hook_socket(int, int, int);

#ifdef __cplusplus
}
#endif

#endif // NETSYS_SOCK_CLIENT_H

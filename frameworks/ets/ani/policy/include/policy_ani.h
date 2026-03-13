/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef POLICY_ANI_H
#define POLICY_ANI_H

#include "cxx.h"
#include "net_policy_client.h"

namespace OHOS {
namespace NetManagerAni {

struct NetAccessPolicyInner;

NetAccessPolicyInner GetSelfNetworkAccessPolicy(int32_t &ret);
rust::String GetErrorCodeAndMessage(int32_t &errorCode);

} // namespace NetManagerAni
} // namespace OHOS

#endif // POLICY_ANI_H

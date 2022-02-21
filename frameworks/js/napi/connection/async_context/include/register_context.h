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

#ifndef NETMANAGER_BASE_REGISTER_CONTEXT_H
#define NETMANAGER_BASE_REGISTER_CONTEXT_H

#include "napi/native_api.h"
#include "net_all_capabilities.h"
#include "net_handle.h"
#include "net_link_info.h"
#include "netmanager_base_base_context.h"
#include "noncopyable.h"

namespace OHOS::NetManagerStandard {
class RegisterContext final : public BaseContext {
public:
    ACE_DISALLOW_COPY_AND_MOVE(RegisterContext);

    RegisterContext() = delete;

    explicit RegisterContext(napi_env env, EventManager *manager);

    void ParseParams(napi_value *params, size_t paramsCount);

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);
};

typedef RegisterContext UnregisterContext;
} // namespace OHOS::NetManagerStandard

#endif /* NETMANAGER_BASE_REGISTER_CONTEXT_H */

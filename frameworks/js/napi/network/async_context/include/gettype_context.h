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

#ifndef NETMANAGER_BASE_GETTYPE_CONTEXT_H
#define NETMANAGER_BASE_GETTYPE_CONTEXT_H

#include "napi/native_api.h"
#include "base_context.h"
#include "nocopyable.h"
#include "net_all_capabilities.h"

namespace OHOS::NetManagerStandard {
class GetTypeContext final : public BaseContext {
public:
    DISALLOW_COPY_AND_MOVE(GetTypeContext);

    GetTypeContext() = delete;

    ~GetTypeContext() override;

    explicit GetTypeContext(napi_env env, std::shared_ptr<EventManager>& manager);

    void ParseParams(napi_value *params, size_t paramsCount);

    [[nodiscard]] napi_value GetSuccessCallback() const;

    [[nodiscard]] napi_value GetFailCallback() const;

    [[nodiscard]] napi_value GetCompleteCallback() const;

    void SetCap(const NetAllCapabilities &cap_);

    NetAllCapabilities GetCap();

private:
    bool SetSuccessCallback(napi_value options);

    bool SetFailCallback(napi_value options);

    bool SetCompleteCallback(napi_value options);

    bool CheckParamsType(napi_value *params, size_t paramsCount);

    NetAllCapabilities cap_;

    napi_ref successCallback_;

    napi_ref failCallback_;

    napi_ref completeCallback_;
};
} // namespace OHOS::NetManagerStandard

#endif /* NETMANAGER_BASE_GETTYPE_CONTEXT_H */

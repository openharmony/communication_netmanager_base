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

#include "parse_nethandle_context.h"

#include "constant.h"
#include "napi_constant.h"
#include "napi_utils.h"

namespace OHOS::NetManagerStandard {
ParseNetHandleContext::ParseNetHandleContext(napi_env env, std::shared_ptr<EventManager>& manager)
    : BaseContext(env, manager) {}

void ParseNetHandleContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(params, paramsCount)) {
        SetErrorCode(NETMANAGER_ERR_PARAMETER_ERROR);
        return;
    }

    auto value = NapiUtils::GetNamedProperty(GetEnv(), params[ARG_INDEX_0], KEY_NET_ID);
    if (NapiUtils::GetValueType(GetEnv(), value) != napi_number) {
        SetErrorCode(NETMANAGER_ERR_PARAMETER_ERROR);
        return;
    }

    int32_t netId_ = NapiUtils::GetInt32Property(GetEnv(), params[ARG_INDEX_0], KEY_NET_ID);
    netHandle_.SetNetId(netId_);

    SetParseOK(true);
}

bool ParseNetHandleContext::CheckParamsType(napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_0]) == napi_object) {
            return true;
        }
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_1]) != napi_function) {
            return false;
        }
        auto status = SetCallback(params[ARG_INDEX_1]);
        if (NapiUtils::GetValueType(GetEnv(), params[ARG_INDEX_0]) != napi_object) {
            return false;
        }
        return (status == napi_ok);
    }

    return false;
}
} // namespace OHOS::NetManagerStandard

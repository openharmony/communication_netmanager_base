/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "setglobalhttpproxy_context.h"

#include "napi_constant.h"
#include "napi_utils.h"
#include "netmanager_base_log.h"

namespace OHOS {
namespace NetManagerStandard {
namespace {

bool CheckParamsType(napi_env env, napi_value *params, size_t paramsCount)
{
    if (paramsCount == PARAM_JUST_OPTIONS) {
        return NapiUtils::GetValueType(env, params[ARG_INDEX_0]) == napi_object;
    }

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        return NapiUtils::GetValueType(env, params[ARG_INDEX_0]) == napi_object &&
               NapiUtils::GetValueType(env, params[ARG_INDEX_1]) == napi_function;
    }
    return false;
}
} // namespace

SetGlobalHttpProxyContext::SetGlobalHttpProxyContext(napi_env env, std::shared_ptr<EventManager>& manager)
    : BaseContext(env, manager) {}

void SetGlobalHttpProxyContext::ParseParams(napi_value *params, size_t paramsCount)
{
    if (!CheckParamsType(GetEnv(), params, paramsCount)) {
        NETMANAGER_BASE_LOGE("check params type failed");
        SetNeedThrowException(true);
        SetErrorCode(NETMANAGER_ERR_PARAMETER_ERROR);
        return;
    }

    httpProxy_.SetHost(NapiUtils::GetStringPropertyUtf8(GetEnv(), params[0], "host"));
    httpProxy_.SetPort(static_cast<uint16_t>(NapiUtils::GetUint32Property(GetEnv(), params[0], "port")));
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], "username")) {
        SecureData secData = NapiUtils::GetSecureDataPropertyUtf8(GetEnv(), params[0], "username");
        httpProxy_.SetUserName(secData);
    }
    if (NapiUtils::HasNamedProperty(GetEnv(), params[0], "password")) {
        SecureData secData = NapiUtils::GetSecureDataPropertyUtf8(GetEnv(), params[0], "password");
        httpProxy_.SetPassword(secData);
    }

    std::list<std::string> exclusionList;
    napi_value exclusionValue = NapiUtils::GetNamedProperty(GetEnv(), params[0], "exclusionList");
    uint32_t listLength = NapiUtils::GetArrayLength(GetEnv(), exclusionValue);
    for (uint32_t i = 0; i < listLength; ++i) {
        napi_value element = NapiUtils::GetArrayElement(GetEnv(), exclusionValue, i);
        exclusionList.push_back(NapiUtils::GetStringFromValueUtf8(GetEnv(), element));
    }
    httpProxy_.SetExclusionList(exclusionList);
    httpProxy_.SetUserId(-1);

    if (paramsCount == PARAM_OPTIONS_AND_CALLBACK) {
        SetParseOK(SetCallback(params[ARG_INDEX_1]) == napi_ok);
        return;
    }

    SetParseOK(true);
}
} // namespace NetManagerStandard
} // namespace OHOS

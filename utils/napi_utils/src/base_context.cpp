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

#include "base_context.h"

#include <limits>

#include "napi_utils.h"
#include "node_api.h"

namespace OHOS {
namespace NetManagerStandard {
BaseContext::BaseContext(napi_env env, std::shared_ptr<EventManager>& manager)
    : manager_(manager),
      env_(env),
      parseOK_(false),
      requestOK_(false),
      errorCode_(std::numeric_limits<int32_t>::max()),
      callback_(nullptr),
      asyncWork_(nullptr),
      deferred_(nullptr),
      needPromise_(true),
      needThrowException_(false)
{
}

BaseContext::~BaseContext()
{
    DeleteCallback();
    DeleteAsyncWork();
}

void BaseContext::SetParseOK(bool parseOK)
{
    parseOK_ = parseOK;
}

void BaseContext::SetErrorCode(int32_t errorCode)
{
    errorCode_ = errorCode;
    errorMessage_ = convertor_.ConvertErrorCode(errorCode_);
}

void BaseContext::SetExecOK(bool requestOK)
{
    requestOK_ = requestOK;
}

void BaseContext::SetError(int32_t errorCode, const std::string &errorMessage)
{
    errorCode_ = errorCode;
    errorMessage_ = errorMessage;
}

napi_status BaseContext::SetCallback(napi_value callback)
{
    if (callback_ != nullptr) {
        (void)napi_delete_reference(env_, callback_);
    }
    return napi_create_reference(env_, callback, 1, &callback_);
}

void BaseContext::DeleteCallback()
{
    if (callback_ == nullptr) {
        return;
    }
    (void)napi_delete_reference(env_, callback_);
    callback_ = nullptr;
}

void BaseContext::CreateAsyncWork(const std::string &name, AsyncWorkExecutor executor, AsyncWorkCallback callback)
{
    napi_status ret = napi_create_async_work(env_, nullptr, NapiUtils::CreateStringUtf8(env_, name), executor, callback,
                                             this, &asyncWork_);
    if (ret != napi_ok) {
        return;
    }
    asyncWorkName_ = name;
    (void)napi_queue_async_work_with_qos(env_, asyncWork_, napi_qos_default);
}

void BaseContext::DeleteAsyncWork()
{
    if (asyncWork_ == nullptr) {
        return;
    }
    (void)napi_delete_async_work(env_, asyncWork_);
}

napi_value BaseContext::CreatePromise()
{
    napi_value result = nullptr;
    NAPI_CALL(env_, napi_create_promise(env_, &deferred_, &result));
    deferredBack1_ = deferred_;
    deferredBack2_ = deferred_;
    deferredBack3_ = deferred_;
    deferredBack4_ = deferred_;
    return result;
}

bool BaseContext::IsParseOK() const
{
    return parseOK_;
}

bool BaseContext::IsExecOK() const
{
    return requestOK_;
}

napi_env BaseContext::GetEnv() const
{
    return env_;
}

int32_t BaseContext::GetErrorCode() const
{
    return errorCode_;
}

const std::string &BaseContext::GetErrorMessage() const
{
    return errorMessage_;
}

napi_value BaseContext::GetCallback() const
{
    if (callback_ == nullptr) {
        return nullptr;
    }
    napi_value callback = nullptr;
    NAPI_CALL(env_, napi_get_reference_value(env_, callback_, &callback));
    return callback;
}

napi_deferred BaseContext::GetDeferred() const
{
    return deferred_;
}

const std::string &BaseContext::GetAsyncWorkName() const
{
    return asyncWorkName_;
}

void BaseContext::Emit(const std::string &type, const std::pair<napi_value, napi_value> &argv)
{
    if (manager_ != nullptr) {
        manager_->Emit(type, argv);
    }
}

std::shared_ptr<EventManager> BaseContext::GetManager() const
{
    return manager_;
}

void BaseContext::SetNeedPromise(bool needPromise)
{
    needPromise_ = needPromise;
}

bool BaseContext::IsNeedPromise() const
{
    return needPromise_;
}

void BaseContext::SetNeedThrowException(bool needThrowException)
{
    needThrowException_ = needThrowException;
}

bool BaseContext::IsNeedThrowException() const
{
    return needThrowException_;
}
} // namespace NetManagerStandard
} // namespace OHOS

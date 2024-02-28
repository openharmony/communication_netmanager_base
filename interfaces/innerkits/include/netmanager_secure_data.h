/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef NETMANAGER_SECURE_DATA_H
#define NETMANAGER_SECURE_DATA_H

#include "memory.h"
#include "securec.h"

namespace OHOS {
namespace NetManagerStandard {
struct SecureData : public std::string {
    ~SecureData()
    {
        // Clear Data, to keep the memory safe
        (void)memset_s(data(), size(), 0, size());
    }
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NETMANAGER_SECURE_DATA_H
/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "netshare_result_callback_proxy.h"

namespace OHOS {
namespace NetManagerStandard {
using namespace testing::ext;
constexpr int32_t RESULT_VALUE = 1;
class NetShareResultCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static inline auto instance_ = std::make_shared<NetShareResultCallbackProxy>(nullptr);
};

void NetShareResultCallbackProxyTest::SetUpTestCase() {}

void NetShareResultCallbackProxyTest::TearDownTestCase() {}

void NetShareResultCallbackProxyTest::SetUp() {}

void NetShareResultCallbackProxyTest::TearDown() {}


HWTEST_F(NetShareResultCallbackProxyTest, OnResultTest, TestSize.Level1)
{
    int32_t result = RESULT_VALUE;
    instance_->OnResult(result);
    EXPECT_EQ(result, RESULT_VALUE);
}

} // namespace NetManagerStandard
} // namespace OHOS
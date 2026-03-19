// Copyright (C) 2026 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{bridge, error_code::convert_to_business_error, policy_error, wrapper::NetPolicyClient};
use ani_rs::business_error::BusinessError;

#[ani_rs::native]
pub fn get_net_access_policy() -> Result<bridge::NetAccessPolicyInner, BusinessError> {
    let raw_result = NetPolicyClient::get_self_network_access_policy();
    raw_result
        .map(|v| { v })
        .map_err(|e| {
            convert_to_business_error(e)
        })
}

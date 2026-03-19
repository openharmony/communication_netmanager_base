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

use crate::bridge;
use ffi::NetAccessPolicyInner;

pub struct NetPolicyClient;

impl NetPolicyClient {
    pub fn get_self_network_access_policy() -> Result<bridge::NetAccessPolicyInner, i32> {
        let mut ret = 0;
        let policy = ffi::GetSelfNetworkAccessPolicy(&mut ret);
        if ret != 0 {
            return Err(ret);
        }
        let result = policy.into();
        Ok(result)
    }
}

impl From<ffi::NetAccessPolicyInner> for bridge::NetAccessPolicyInner {
    fn from(policy: ffi::NetAccessPolicyInner) -> Self {
        bridge::NetAccessPolicyInner {
            allow_wiFi: policy.allowWiFi,
            allow_cellular: policy.allowCellular,
        }
    }
}

#[cxx::bridge(namespace = "OHOS::NetManagerAni")]
pub mod ffi {
    pub struct NetAccessPolicyInner {
        pub allowWiFi: bool,
        pub allowCellular: bool,
    }

    unsafe extern "C++" {
        include!("policy_ani.h");

        fn GetSelfNetworkAccessPolicy(ret: &mut i32) -> NetAccessPolicyInner;
        fn GetErrorCodeAndMessage(error_code: &mut i32) -> String;
    }
}

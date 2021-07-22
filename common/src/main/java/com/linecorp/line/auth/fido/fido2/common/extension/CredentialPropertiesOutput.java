/*
 * Copyright 2021 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.line.auth.fido.fido2.common.extension;

import lombok.Data;

@Data
public class CredentialPropertiesOutput {
    // if rk is true, resident key (able to authenticate without allow list)
    // if rk is false, non-resident key (should have allow list during authentication)
    // if rk is null, we don't know whether it is resident key or non-resident key
    private Boolean rk;
}

/*
 * Copyright 2024 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
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

import java.util.List;

import lombok.Data;

@Data
public class AuthenticationExtensionsClientOutputs {
    private Boolean appid;
    private String txAuthSimple;
    private String txAuthGeneric;
    private Boolean authnSel;
    private List<String> exts;
    private String uvi;
    private Coordinates loc;
    private Boolean biometricPerfBounds;
    private CredentialPropertiesOutput credProps;
    private PRFOutputs prf;
}

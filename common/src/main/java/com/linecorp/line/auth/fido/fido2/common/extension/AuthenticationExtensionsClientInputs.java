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

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.ToString;

import java.util.List;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

@Data
@JsonInclude(NON_NULL)
@ToString
public class AuthenticationExtensionsClientInputs {
    private String appid;
    private String txAuthSimple;
    private TxAuthGenericAlg txAuthGeneric;
    private List<String> authnSel;
    private List<String> line_authnSel;
    private Boolean exts;
    private Boolean uvi;
    private Boolean loc;
    private AuthenticatorBiometricPerfBounds biometricPerfBounds;
    private Boolean credProps;  // credential properties extension for getting credential properties during registration (WebAuthn Level2)

    // Credential Protection (credProtect)
    private CredentialProtectionPolicy credentialProtectionPolicy;
    private Boolean enforceCredentialProtectionPolicy;  // if true, it should fail
}

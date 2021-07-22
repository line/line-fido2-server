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

package com.linecorp.line.auth.fido.fido2.common.server;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.linecorp.line.auth.fido.fido2.common.AuthenticatorAttachment;
import com.linecorp.line.auth.fido.fido2.common.AuthenticatorTransport;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(NON_NULL)
public class RegisterCredentialResult implements ServerAPIResult {
    private ServerResponse serverResponse;
    private String aaguid;
    private String credentialId;
    private AuthenticatorAttachment authenticatorAttachment;
    private AttestationType attestationType;
    private List<AuthenticatorTransport> authenticatorTransports;   // list of available authenticator transport
    private boolean userVerified;
    private Boolean rk; // RP can decided UX flow by looking at this
    private Integer credProtect;
}

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

package com.linecorp.line.auth.fido.fido2.rpserver.model.transport;

import com.linecorp.line.auth.fido.fido2.common.UserVerificationRequirement;
import com.linecorp.line.auth.fido.fido2.common.extension.AuthenticationExtensionsClientInputs;
import com.linecorp.line.auth.fido.fido2.common.server.ServerPublicKeyCredentialDescriptor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ServerPublicKeyCredentialGetOptionsResponse extends AdapterServerResponse {
    private String challenge;
    private long timeout;
    private String rpId;
    @JsonInclude(Include.NON_NULL)
    private List<ServerPublicKeyCredentialDescriptor> allowCredentials;
    @JsonInclude(Include.NON_NULL)
    private UserVerificationRequirement userVerification;
    //extensions
    private AuthenticationExtensionsClientInputs extensions;
}

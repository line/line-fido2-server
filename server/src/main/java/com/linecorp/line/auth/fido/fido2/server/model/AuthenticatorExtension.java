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

package com.linecorp.line.auth.fido.fido2.server.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.linecorp.line.auth.fido.fido2.common.extension.CredentialProtectionPolicy;
import com.linecorp.line.auth.fido.fido2.common.extension.SupportedExtensions;
import lombok.Data;

import java.io.ByteArrayInputStream;
import java.io.IOException;

@Data
public class AuthenticatorExtension {
    private CredentialProtectionPolicy credProtect;

    public static AuthenticatorExtension decode(byte[] input) throws IOException {
        AuthenticatorExtension authenticatorExtension = new AuthenticatorExtension();
        CredentialProtectionPolicy credProtect = null;

        ByteArrayInputStream inputStream = new ByteArrayInputStream(input);
        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper objectMapper = new ObjectMapper(cborFactory);

        JsonNode node = objectMapper.readTree(inputStream);

        if (node == null) {
            throw new IOException("No input for Extension");
        }

        JsonNode credProtectNode = node.get(SupportedExtensions.CRED_PROTECT);

        // credProtect
        if (credProtectNode != null) {
            if (credProtectNode.isNumber()) {
                credProtect = CredentialProtectionPolicy.fromValue(credProtectNode.asInt());
            }
        }

        authenticatorExtension.setCredProtect(credProtect);
        return authenticatorExtension;
    }
}

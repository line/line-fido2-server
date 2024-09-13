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

package com.linecorp.line.auth.fido.fido2.common.server.bean.validation;

import com.linecorp.line.auth.fido.fido2.common.server.RegisterCredential;
import com.linecorp.line.auth.fido.fido2.common.server.ServerAuthenticatorAttestationResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.validation.ConstraintViolation;
import java.io.IOException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ServerAuthenticatorAttestationResponseBeanValidationTest extends BeanValidationTestSupport {

    private static ServerAuthenticatorAttestationResponse origin;
    private ServerAuthenticatorAttestationResponse serverAuthenticatorAttestationResponse;

    @BeforeAll
    static void initGlobal() throws IOException {
        final RegisterCredential registerCredential = objectMapper.readValue(RegisterCredential.class.getResourceAsStream("/json/reg/reg-response-req.json"), RegisterCredential.class);
        origin = registerCredential.getServerPublicKeyCredential().getResponse();
    }

    @BeforeEach
    void setUp() throws IOException {
        //Deep copy
        serverAuthenticatorAttestationResponse = objectMapper.readValue(objectMapper.writeValueAsString(origin), ServerAuthenticatorAttestationResponse.class);
    }

    @Test
    void validateSuccessfulRequest() {
        final Set<ConstraintViolation<ServerAuthenticatorAttestationResponse>> constraintViolations = validator.validate(serverAuthenticatorAttestationResponse);
        assertThat(constraintViolations).isEmpty();
    }

    @Test
    void validateIncompleteRequestWithBlank() {

        serverAuthenticatorAttestationResponse.setAttestationObject("");
        serverAuthenticatorAttestationResponse.setClientDataJSON("");

        final Set<ConstraintViolation<ServerAuthenticatorAttestationResponse>> constraintViolations = validator.validate(serverAuthenticatorAttestationResponse);

        assertThat(constraintViolations).hasSize(2);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(MUST_NOT_BE_BLANK);
    }

    @Test
    void validateIncompleteRequestWithInvalidBase64Url() {

        final String attestationObject = serverAuthenticatorAttestationResponse.getAttestationObject() + NOT_VALID_BASE64_URL_STRING;
        serverAuthenticatorAttestationResponse.setAttestationObject(attestationObject);

        final String clientDataJson = serverAuthenticatorAttestationResponse.getClientDataJSON() + NOT_VALID_BASE64_URL_STRING;
        serverAuthenticatorAttestationResponse.setClientDataJSON(clientDataJson);

        final Set<ConstraintViolation<ServerAuthenticatorAttestationResponse>> constraintViolations = validator.validate(serverAuthenticatorAttestationResponse);

        assertThat(constraintViolations).hasSize(2);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(MUST_BE_A_WELL_FORMED_BASE_64);
    }
}

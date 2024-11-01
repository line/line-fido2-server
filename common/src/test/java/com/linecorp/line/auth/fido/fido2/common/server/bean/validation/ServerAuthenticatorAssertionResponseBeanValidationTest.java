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

import com.linecorp.line.auth.fido.fido2.common.server.ServerAuthenticatorAssertionResponse;
import com.linecorp.line.auth.fido.fido2.common.server.VerifyCredential;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.validation.ConstraintViolation;
import java.io.IOException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ServerAuthenticatorAssertionResponseBeanValidationTest extends BeanValidationTestSupport {
    private static ServerAuthenticatorAssertionResponse origin;
    private ServerAuthenticatorAssertionResponse serverAuthenticatorAssertionResponse;

    @BeforeAll
    static void initGlobal() throws IOException {
        origin = objectMapper.readValue(VerifyCredential.class.getResourceAsStream("/json/auth/auth-response-req.json"), VerifyCredential.class).getServerPublicKeyCredential().getResponse();
    }

    @BeforeEach
    void setUp() throws IOException {
        //Deep copy
        serverAuthenticatorAssertionResponse = objectMapper.readValue(objectMapper.writeValueAsString(origin), ServerAuthenticatorAssertionResponse.class);
    }

    @Test
    void validateSuccessfulRequest() {
        final Set<ConstraintViolation<ServerAuthenticatorAssertionResponse>> constraintViolations = validator.validate(serverAuthenticatorAssertionResponse);
        assertThat(constraintViolations).isEmpty();
    }

    @Test
    void validateIncompleteRequestWithBlank() {

        serverAuthenticatorAssertionResponse.setAuthenticatorData("");
        serverAuthenticatorAssertionResponse.setClientDataJSON("");
        serverAuthenticatorAssertionResponse.setSignature("");

        final Set<ConstraintViolation<ServerAuthenticatorAssertionResponse>> constraintViolations = validator.validate(serverAuthenticatorAssertionResponse);

        assertThat(constraintViolations).hasSize(3);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(MUST_NOT_BE_BLANK);
    }

    @Test
    void validateIncompleteRequestWithInvalidBase64Url() {

        final String authenticatorData = serverAuthenticatorAssertionResponse.getAuthenticatorData() + NOT_VALID_BASE64_URL_STRING;
        serverAuthenticatorAssertionResponse.setAuthenticatorData(authenticatorData);

        final String clientDataJSON = serverAuthenticatorAssertionResponse.getClientDataJSON() + NOT_VALID_BASE64_URL_STRING;
        serverAuthenticatorAssertionResponse.setClientDataJSON(clientDataJSON);

        final String signature = serverAuthenticatorAssertionResponse.getSignature() + NOT_VALID_BASE64_URL_STRING;
        serverAuthenticatorAssertionResponse.setSignature(signature);

        final Set<ConstraintViolation<ServerAuthenticatorAssertionResponse>> constraintViolations = validator.validate(serverAuthenticatorAssertionResponse);

        assertThat(constraintViolations).hasSize(3);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(MUST_BE_A_WELL_FORMED_BASE_64);
    }
}

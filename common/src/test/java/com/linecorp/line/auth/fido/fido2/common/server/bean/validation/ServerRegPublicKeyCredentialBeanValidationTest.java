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
import com.linecorp.line.auth.fido.fido2.common.server.ServerRegPublicKeyCredential;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.validation.ConstraintViolation;
import java.io.IOException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ServerRegPublicKeyCredentialBeanValidationTest extends BeanValidationTestSupport {

    private static ServerRegPublicKeyCredential origin;
    private ServerRegPublicKeyCredential serverRegPublicKeyCredential;

    @BeforeAll
    static void initGlobal() throws IOException {
        final RegisterCredential registerCredential = objectMapper.readValue(RegisterCredential.class.getResourceAsStream("/json/reg/reg-response-req.json"), RegisterCredential.class);
        origin = registerCredential.getServerPublicKeyCredential();
    }

    @BeforeEach
    void setUp() throws IOException {
        //Deep copy
        serverRegPublicKeyCredential = objectMapper.readValue(objectMapper.writeValueAsString(origin), ServerRegPublicKeyCredential.class);
    }

    @Test
    void validateSuccessfulRequest() {
        final Set<ConstraintViolation<ServerRegPublicKeyCredential>> constraintViolations = validator.validate(serverRegPublicKeyCredential);
        assertThat(constraintViolations).isEmpty();
    }

    @Test
    void validateIncompleteRequestWithNull() {

        serverRegPublicKeyCredential.setResponse(null);

        final Set<ConstraintViolation<ServerRegPublicKeyCredential>> constraintViolations = validator.validate(serverRegPublicKeyCredential);

        assertThat(constraintViolations).hasSize(1);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(MUST_NOT_BE_NULL);
    }
}

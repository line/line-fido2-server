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

import com.linecorp.line.auth.fido.fido2.common.server.RegOptionRequest;
import com.linecorp.line.auth.fido.fido2.common.server.ServerPublicKeyCredentialUserEntity;
import org.assertj.core.internal.bytebuddy.utility.RandomString;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.validation.ConstraintViolation;
import java.io.IOException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ServerPublicKeyCredentialUserEntityBeanValidationTest extends BeanValidationTestSupport {

    private static ServerPublicKeyCredentialUserEntity origin;
    private ServerPublicKeyCredentialUserEntity serverPublicKeyCredentialUserEntity;

    @BeforeAll
    static void initGlobal() throws IOException {
        origin = objectMapper.readValue(RegOptionRequest.class.getResourceAsStream("/json/reg/reg-challenge-req.json"), RegOptionRequest.class).getUser();
    }

    @BeforeEach
    void setUp() throws IOException {
        //Deep copy
        serverPublicKeyCredentialUserEntity = objectMapper.readValue(objectMapper.writeValueAsString(origin), ServerPublicKeyCredentialUserEntity.class);
    }

    @Test
    void validateSuccessfulRequest() {
        final Set<ConstraintViolation<ServerPublicKeyCredentialUserEntity>> constraintViolations = validator.validate(serverPublicKeyCredentialUserEntity);
        assertThat(constraintViolations).isEmpty();
    }

    @Test
    void validateIncompleteRequestWithTooLongId() {

        serverPublicKeyCredentialUserEntity.setId(RandomString.make(65));
        final Set<ConstraintViolation<ServerPublicKeyCredentialUserEntity>> constraintViolations = validator.validate(serverPublicKeyCredentialUserEntity);

        assertThat(constraintViolations).hasSize(1);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(LENGTH_MUST_BE_BETWEEN_1_AND_64);
    }

    @Test
    void validateIncompleteRequestWithTooShortId() {

        serverPublicKeyCredentialUserEntity.setId("");
        final Set<ConstraintViolation<ServerPublicKeyCredentialUserEntity>> constraintViolations = validator.validate(serverPublicKeyCredentialUserEntity);

        assertThat(constraintViolations).hasSize(1);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(LENGTH_MUST_BE_BETWEEN_1_AND_64);
    }
}

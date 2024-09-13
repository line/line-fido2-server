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

import com.linecorp.line.auth.fido.fido2.common.server.AuthOptionRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.validation.ConstraintViolation;
import java.io.IOException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AuthOptionRequestBeanValidationTest extends BeanValidationTestSupport {

    private static AuthOptionRequest origin;
    private AuthOptionRequest authOptionRequest;

    @BeforeAll
    static void initGlobal() throws IOException {
        origin = objectMapper.readValue(AuthOptionRequest.class.getResourceAsStream("/json/auth/auth-challenge-req.json"), AuthOptionRequest.class);
    }

    @BeforeEach
    void setUp() throws IOException {
        //Deep copy
        authOptionRequest = objectMapper.readValue(objectMapper.writeValueAsString(origin), AuthOptionRequest.class);
    }

    @Test
    void validateSuccessfulRequest() {
        final Set<ConstraintViolation<AuthOptionRequest>> constraintViolations = validator.validate(authOptionRequest);
        assertThat(constraintViolations).isEmpty();
    }

    @Test
    void validateIncompleteRequestWithBlank() {

        authOptionRequest.setRpId("");

        final Set<ConstraintViolation<AuthOptionRequest>> constraintViolations = validator.validate(authOptionRequest);

        assertThat(constraintViolations).hasSize(1);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(MUST_NOT_BE_BLANK);
    }
}

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
package com.linecorp.line.auth.fido.fido2.common.server.bean.validation;

import com.linecorp.line.auth.fido.fido2.common.server.VerifyCredential;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.validation.ConstraintViolation;
import java.io.IOException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class VerifyCredentialBeanValidationTest extends BeanValidationTestSupport {

    private static VerifyCredential origin;
    private VerifyCredential verifyCredential;

    @BeforeAll
    static void initGlobal() throws IOException {
        origin = objectMapper.readValue(VerifyCredential.class.getResourceAsStream("/json/auth/auth-response-req.json"), VerifyCredential.class);
    }

    @BeforeEach
    void setUp() throws IOException {
        //Deep copy
        verifyCredential = objectMapper.readValue(objectMapper.writeValueAsString(origin), VerifyCredential.class);
    }

    @Test
    void validateSuccessfulRequest() {
        final Set<ConstraintViolation<VerifyCredential>> constraintViolations = validator.validate(verifyCredential);
        assertThat(constraintViolations).isEmpty();
    }

    @Test
    void validateIncompleteRequestWithBlank() {

        verifyCredential.setOrigin("");
        verifyCredential.setRpId("");
        verifyCredential.setSessionId("");

        final Set<ConstraintViolation<VerifyCredential>> constraintViolations = validator.validate(verifyCredential);

        assertThat(constraintViolations).hasSize(3);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(MUST_NOT_BE_BLANK);
    }
}
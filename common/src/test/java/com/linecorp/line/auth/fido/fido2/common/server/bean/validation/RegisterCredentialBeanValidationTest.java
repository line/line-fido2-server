package com.linecorp.line.auth.fido.fido2.common.server.bean.validation;

import com.linecorp.line.auth.fido.fido2.common.server.RegisterCredential;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.validation.ConstraintViolation;
import java.io.IOException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RegisterCredentialBeanValidationTest extends BeanValidationTestSupport {

    private static RegisterCredential origin;
    private RegisterCredential registerCredential;

    @BeforeAll
    static void initGlobal() throws IOException {
        origin = objectMapper.readValue(RegisterCredential.class.getResourceAsStream("/json/reg/reg-response-req.json"), RegisterCredential.class);
    }

    @BeforeEach
    void setUp() throws IOException {
        //Deep copy
        registerCredential = objectMapper.readValue(objectMapper.writeValueAsString(origin), RegisterCredential.class);
    }

    @Test
    void validateSuccessfulRequest() {
        final Set<ConstraintViolation<RegisterCredential>> constraintViolations = validator.validate(registerCredential);
        assertThat(constraintViolations).isEmpty();
    }

    @Test
    void validateIncompleteRequestWithNull() {

        registerCredential.setServerPublicKeyCredential(null);

        final Set<ConstraintViolation<RegisterCredential>> constraintViolations = validator.validate(registerCredential);

        assertThat(constraintViolations).hasSize(1);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(MUST_NOT_BE_NULL);
    }

    @Test
    void validateIncompleteRequestWithBlank() {

        registerCredential.setOrigin("");
        registerCredential.setRpId("");
        registerCredential.setSessionId("");

        final Set<ConstraintViolation<RegisterCredential>> constraintViolations = validator.validate(registerCredential);

        assertThat(constraintViolations).hasSize(3);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(MUST_NOT_BE_BLANK);
    }
}
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
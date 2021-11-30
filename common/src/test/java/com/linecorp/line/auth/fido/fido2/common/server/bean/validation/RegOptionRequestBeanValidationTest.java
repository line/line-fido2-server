package com.linecorp.line.auth.fido.fido2.common.server.bean.validation;

import com.linecorp.line.auth.fido.fido2.common.server.RegOptionRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.validation.ConstraintViolation;
import java.io.IOException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RegOptionRequestBeanValidationTest extends BeanValidationTestSupport {

    private static RegOptionRequest origin;
    private RegOptionRequest regOptionRequest;

    @BeforeAll
    static void initGlobal() throws IOException {
        origin = objectMapper.readValue(RegOptionRequest.class.getResourceAsStream("/json/reg/reg-challenge-req.json"), RegOptionRequest.class);
    }

    @BeforeEach
    void setUp() throws IOException {
        //Deep copy
        regOptionRequest = objectMapper.readValue(objectMapper.writeValueAsString(origin), RegOptionRequest.class);
    }

    @Test
    void validateSuccessfulRequest() {
        final Set<ConstraintViolation<RegOptionRequest>> constraintViolations = validator.validate(regOptionRequest);
        assertThat(constraintViolations).isEmpty();
    }

    @Test
    void validateIncompleteRequestWithNull() {

        regOptionRequest.setRp(null);
        regOptionRequest.setUser(null);

        final Set<ConstraintViolation<RegOptionRequest>> constraintViolations = validator.validate(regOptionRequest);

        assertThat(constraintViolations).hasSize(2);
        assertThat(constraintViolations).extracting(ConstraintViolation::getMessage)
                .containsOnly(MUST_NOT_BE_NULL);
    }
}
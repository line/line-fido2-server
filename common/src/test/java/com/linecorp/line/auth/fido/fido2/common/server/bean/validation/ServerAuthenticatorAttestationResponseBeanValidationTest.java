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
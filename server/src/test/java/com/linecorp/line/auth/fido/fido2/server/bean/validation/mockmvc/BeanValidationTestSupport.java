package com.linecorp.line.auth.fido.fido2.server.bean.validation.mockmvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@AutoConfigureMockMvc
public class BeanValidationTestSupport {

    protected static final String REG_CHALLENGE_URL_PATH = "/fido2/reg/challenge";
    protected static final String REG_RESPONSE_URL_PATH = "/fido2/reg/response";
    protected static final String AUTH_CHALLENGE_URL_PATH = "/fido2/auth/challenge";
    protected static final String AUTH_RESPONSE_URL_PATH = "/fido2/auth/response";

    protected static final ObjectMapper objectMapper = new ObjectMapper();

}

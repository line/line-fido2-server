package com.linecorp.line.auth.fido.fido2.server.bean.validation.mockmvc;

import com.linecorp.line.auth.fido.fido2.common.server.VerifyCredential;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthResponseRequestBeanValidationTest extends BeanValidationTestSupport {

    private MockMvc mockMvc;
    private static VerifyCredential origin;
    private VerifyCredential authResponseRequest;

    @BeforeAll
    static void initGlobal() throws IOException {
        origin = objectMapper.readValue(VerifyCredential.class.getResourceAsStream("/json/auth/auth-response-req.json"), VerifyCredential.class);
    }

    @BeforeEach
    void setUp(final WebApplicationContext context) throws IOException {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .alwaysDo(MockMvcResultHandlers.print())
                .build();

        //Deep copy
        authResponseRequest = objectMapper.readValue(objectMapper.writeValueAsString(origin), VerifyCredential.class);
    }

    @Test
    void validateSuccessfulRequest() throws Exception {

        mockMvc.perform(post(AUTH_RESPONSE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authResponseRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void validateIncompleteRequestShouldReturnMethodArgumentNotValidException() throws Exception {

        authResponseRequest.setRpId("");

        mockMvc.perform(post(AUTH_RESPONSE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authResponseRequest)))
                .andExpect(result -> assertTrue(result.getResolvedException() instanceof MethodArgumentNotValidException))
                .andExpect(status().isBadRequest());
    }
}

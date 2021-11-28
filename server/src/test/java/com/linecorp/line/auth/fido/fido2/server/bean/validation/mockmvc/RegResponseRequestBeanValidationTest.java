package com.linecorp.line.auth.fido.fido2.server.bean.validation.mockmvc;

import com.linecorp.line.auth.fido.fido2.common.server.RegisterCredential;
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

class RegResponseRequestBeanValidationTest extends BeanValidationTestSupport {

    private MockMvc mockMvc;
    private static RegisterCredential origin;
    private RegisterCredential regResponseRequest;

    @BeforeAll
    static void initGlobal() throws IOException {
        origin = objectMapper.readValue(RegisterCredential.class.getResourceAsStream("/json/reg/reg-response-req.json"), RegisterCredential.class);
    }

    @BeforeEach
    void setUp(final WebApplicationContext context) throws IOException {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .alwaysDo(MockMvcResultHandlers.print())
                .build();

        //Deep copy
        regResponseRequest = objectMapper.readValue(objectMapper.writeValueAsString(origin), RegisterCredential.class);
    }

    @Test
    void validateSuccessfulRequest() throws Exception {

        mockMvc.perform(post(REG_RESPONSE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regResponseRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void validateIncompleteRequestShouldReturnMethodArgumentNotValidException() throws Exception {

        regResponseRequest.setOrigin("");

        mockMvc.perform(post(REG_RESPONSE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regResponseRequest)))
                .andExpect(result -> assertTrue(result.getResolvedException() instanceof MethodArgumentNotValidException))
                .andExpect(status().isBadRequest());
    }
}

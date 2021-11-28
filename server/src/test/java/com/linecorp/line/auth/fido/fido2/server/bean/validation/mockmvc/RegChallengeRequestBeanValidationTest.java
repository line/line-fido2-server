package com.linecorp.line.auth.fido.fido2.server.bean.validation.mockmvc;

import com.linecorp.line.auth.fido.fido2.common.server.RegOptionRequest;
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

class RegChallengeRequestBeanValidationTest extends BeanValidationTestSupport {

    private MockMvc mockMvc;
    private static RegOptionRequest origin;
    private RegOptionRequest regChallengeRequest;

    @BeforeAll
    static void initGlobal() throws IOException {
        origin = objectMapper.readValue(RegOptionRequest.class.getResourceAsStream("/json/reg/reg-challenge-req.json"), RegOptionRequest.class);
    }

    @BeforeEach
    void setUp(final WebApplicationContext context) throws IOException {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .alwaysDo(MockMvcResultHandlers.print())
                .build();

        //Deep copy
        regChallengeRequest = objectMapper.readValue(objectMapper.writeValueAsString(origin), RegOptionRequest.class);
    }

    @Test
    void validateSuccessfulRequest() throws Exception {

        mockMvc.perform(post(REG_CHALLENGE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regChallengeRequest)))
                .andExpect(status().isOk());
    }

    @Test
    void validateIncompleteRequestShouldReturnMethodArgumentNotValidException() throws Exception {

        regChallengeRequest.setRp(null);

        mockMvc.perform(post(REG_CHALLENGE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regChallengeRequest)))
                .andExpect(result -> assertTrue(result.getResolvedException() instanceof MethodArgumentNotValidException))
                .andExpect(status().isBadRequest());
    }
}

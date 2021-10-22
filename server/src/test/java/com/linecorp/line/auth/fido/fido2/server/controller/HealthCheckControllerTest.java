package com.linecorp.line.auth.fido.fido2.server.controller;

import com.linecorp.line.auth.fido.fido2.server.restdocs.TestSupport;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class HealthCheckControllerTest extends TestSupport {

    @Test
    void healthCheck() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(MockMvcResultMatchers.content().string("OK"))
                .andExpect(status().isOk());
    }
}
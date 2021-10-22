package com.linecorp.line.auth.fido.fido2.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.linecorp.line.auth.fido.fido2.common.server.AuthOptionResponse;
import com.linecorp.line.auth.fido.fido2.common.server.RegOptionResponse;
import com.linecorp.line.auth.fido.fido2.server.entity.UserKeyEntity;
import com.linecorp.line.auth.fido.fido2.server.model.Session;
import com.linecorp.line.auth.fido.fido2.server.repository.UserKeyRepository;
import com.linecorp.line.auth.fido.fido2.server.support.restdocs.TestSupportForSpringRestDocs;
import com.linecorp.line.auth.fido.fido2.server.service.SessionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Rollback
@Transactional
class ResponseControllerTest extends TestSupportForSpringRestDocs {

    @Autowired
    private UserKeyRepository userKeyRepository;

    @Autowired
    private SessionService sessionService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void sendRegResponse_success() throws Exception {

        final Session session = sessionService.createSessionData();
        final RegOptionResponse regOptionResponse = objectMapper.readValue(readJson("/json/reg/reg-challenge-res.json"), RegOptionResponse.class);
        session.setRegOptionResponse(regOptionResponse);
        session.setId(regOptionResponse.getSessionId());
        sessionService.createSession(session);

        final String expectedResult = readJson("/json/reg/reg-response-res.json");

        mockMvc.perform(post("/fido2/reg/response")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(readJson("/json/reg/reg-response-req.json"))
                )
                .andExpect(MockMvcResultMatchers.content().json(expectedResult))
                .andExpect(status().isOk());

    }

    @Test
    void sendAuthResponse_success() throws Exception {

        final Session session = sessionService.createSessionData();
        final AuthOptionResponse authOptionResponse = objectMapper.readValue(readJson("/json/auth/auth-challenge-res.json"), AuthOptionResponse.class);
        session.setAuthOptionResponse(authOptionResponse);
        session.setId(authOptionResponse.getSessionId());
        sessionService.createSession(session);

        final UserKeyEntity userKeyEntity = objectMapper.readValue(readJson("/json/database/user-key-entity.json"), UserKeyEntity.class);
        userKeyRepository.save(userKeyEntity);

        final String expectedResult = readJson("/json/auth/auth-response-res.json");

        mockMvc.perform(post("/fido2/auth/response")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(readJson("/json/auth/auth-response-req.json"))
                )
                .andExpect(MockMvcResultMatchers.content().json(expectedResult))
                .andExpect(status().isOk());
    }
}
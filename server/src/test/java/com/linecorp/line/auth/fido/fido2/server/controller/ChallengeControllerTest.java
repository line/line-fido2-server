package com.linecorp.line.auth.fido.fido2.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.linecorp.line.auth.fido.fido2.server.entity.UserKeyEntity;
import com.linecorp.line.auth.fido.fido2.server.repository.UserKeyRepository;
import com.linecorp.line.auth.fido.fido2.server.restdocs.TestSupport;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Rollback
@Transactional
class ChallengeControllerTest extends TestSupport {

    @Autowired
    private UserKeyRepository userKeyRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void getRegChallenge() throws Exception {
        mockMvc.perform(post("/fido2/reg/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(readJson("/json/reg/reg-challenge-req.json"))
                )
                .andExpect(status().isOk())
                .andDo(restDocs.document());
    }

    @Test
    void getAuthChallenge() throws Exception {
        UserKeyEntity userKeyEntity = objectMapper.readValue(readJson("/json/database/user-key-entity.json"), UserKeyEntity.class);
        userKeyRepository.save(userKeyEntity);
        mockMvc.perform(post("/fido2/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(readJson("/json/auth/auth-challenge-req.json"))
                )
                .andExpect(status().isOk())
                .andDo(restDocs.document());
    }
}
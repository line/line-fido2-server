package com.linecorp.line.auth.fido.fido2.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.linecorp.line.auth.fido.fido2.common.server.AuthOptionResponse;
import com.linecorp.line.auth.fido.fido2.common.server.RegOptionResponse;
import com.linecorp.line.auth.fido.fido2.server.entity.UserKeyEntity;
import com.linecorp.line.auth.fido.fido2.server.repository.UserKeyRepository;
import com.linecorp.line.auth.fido.fido2.server.support.restdocs.TestSupportForSpringRestDocs;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.Matchers.*;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Rollback
@Transactional
class ChallengeControllerTest extends TestSupportForSpringRestDocs {

    @Autowired
    private UserKeyRepository userKeyRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void getRegChallenge_success() throws Exception {

        final RegOptionResponse expectedResult = objectMapper.readValue(readJson("/json/reg/reg-challenge-res.json"), RegOptionResponse.class);
        mockMvc.perform(post("/fido2/reg/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(readJson("/json/reg/reg-challenge-req.json"))
                )
                .andExpect(jsonPath("$.challenge", hasLength(expectedResult.getChallenge().length())))
                .andExpect(jsonPath("$.sessionId", hasLength(expectedResult.getSessionId().length())))
                .andExpect(jsonPath("$.pubKeyCredParams", hasSize(expectedResult.getPubKeyCredParams().size())))
                .andExpect(jsonPath("$.user.name", is(expectedResult.getUser().getName())))
                .andExpect(jsonPath("$.user.id", is(expectedResult.getUser().getId())))
                .andExpect(jsonPath("$.serverResponse.internalError", is(expectedResult.getServerResponse().getInternalError())))
                .andExpect(status().isOk());
    }

    @Test
    void getAuthChallenge_success() throws Exception {

        final UserKeyEntity userKeyEntity = objectMapper.readValue(readJson("/json/database/user-key-entity.json"), UserKeyEntity.class);
        userKeyRepository.save(userKeyEntity);

        final AuthOptionResponse expectedResult = objectMapper.readValue(readJson("/json/auth/auth-challenge-res.json"), AuthOptionResponse.class);
        mockMvc.perform(post("/fido2/auth/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(readJson("/json/auth/auth-challenge-req.json"))
                )
                .andExpect(jsonPath("$.challenge", hasLength(expectedResult.getChallenge().length())))
                .andExpect(jsonPath("$.sessionId", hasLength(expectedResult.getSessionId().length())))
                .andExpect(jsonPath("$.allowCredentials", hasSize(expectedResult.getAllowCredentials().size())))
                .andExpect(jsonPath("$.serverResponse.internalError", is(expectedResult.getServerResponse().getInternalError())))
                .andExpect(status().isOk());
    }
}
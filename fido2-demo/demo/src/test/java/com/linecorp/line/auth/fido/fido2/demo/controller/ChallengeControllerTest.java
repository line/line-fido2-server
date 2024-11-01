/*
 * Copyright 2024 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.line.auth.fido.fido2.demo.controller;

import com.linecorp.line.auth.fido.fido2.common.server.AuthOptionRequest;
import com.linecorp.line.auth.fido.fido2.common.server.AuthOptionResponse;
import com.linecorp.line.auth.fido.fido2.common.server.RegOptionRequest;
import com.linecorp.line.auth.fido.fido2.common.server.RegOptionResponse;
import com.linecorp.line.auth.fido.fido2.base.entity.UserKeyEntity;
import com.linecorp.line.auth.fido.fido2.base.repository.UserKeyRepository;
import com.linecorp.line.auth.fido.fido2.demo.support.restdocs.TestSupportForSpringRestDocs;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.MethodArgumentNotValidException;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Rollback
@Transactional
class ChallengeControllerTest extends TestSupportForSpringRestDocs {

    @Autowired
    private UserKeyRepository userKeyRepository;

    @Test
    void getRegChallenge_success() throws Exception {

        final RegOptionResponse expectedResult = objectMapper.readValue(readJson(REG_CHALLENGE_RES_JSON_PATH), RegOptionResponse.class);
        mockMvc.perform(post(REG_CHALLENGE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(readJson(REG_CHALLENGE_REQ_JSON_PATH))
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

        final UserKeyEntity userKeyEntity = objectMapper.readValue(readJson(DATABASE_USER_KEY_ENTITY_JSON_PATH), UserKeyEntity.class);
        userKeyRepository.save(userKeyEntity);

        final AuthOptionResponse expectedResult = objectMapper.readValue(readJson(AUTH_CHALLENGE_RES_JSON_PATH), AuthOptionResponse.class);
        mockMvc.perform(post(AUTH_CHALLENGE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(readJson(AUTH_CHALLENGE_REQ_JSON_PATH))
                )
                .andExpect(jsonPath("$.challenge", hasLength(expectedResult.getChallenge().length())))
                .andExpect(jsonPath("$.sessionId", hasLength(expectedResult.getSessionId().length())))
                .andExpect(jsonPath("$.allowCredentials", hasSize(expectedResult.getAllowCredentials().size())))
                .andExpect(jsonPath("$.serverResponse.internalError", is(expectedResult.getServerResponse().getInternalError())))
                .andExpect(status().isOk());
    }

    @Test
    void validateIncompleteRegRequestShouldReturnMethodArgumentNotValidException() throws Exception {

        final RegOptionRequest regOptionRequest = objectMapper.readValue(readJson(REG_CHALLENGE_REQ_JSON_PATH), RegOptionRequest.class);
        regOptionRequest.setRp(null);

        mockMvc.perform(MockMvcRequestBuilders.post(REG_CHALLENGE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regOptionRequest)))
                .andExpect(result -> assertTrue(result.getResolvedException() instanceof MethodArgumentNotValidException))
                .andExpect(status().isBadRequest());
    }

    @Test
    void validateIncompleteAuthRequestShouldReturnMethodArgumentNotValidException() throws Exception {

        final AuthOptionRequest authOptionRequest = objectMapper.readValue(readJson(AUTH_CHALLENGE_REQ_JSON_PATH), AuthOptionRequest.class);
        authOptionRequest.setRpId("");

        mockMvc.perform(MockMvcRequestBuilders.post(AUTH_CHALLENGE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authOptionRequest)))
                .andExpect(result -> assertTrue(result.getResolvedException() instanceof MethodArgumentNotValidException))
                .andExpect(status().isBadRequest());
    }
}

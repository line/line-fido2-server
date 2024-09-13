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

import com.linecorp.line.auth.fido.fido2.common.server.AuthOptionResponse;
import com.linecorp.line.auth.fido.fido2.common.server.RegOptionResponse;
import com.linecorp.line.auth.fido.fido2.common.server.RegisterCredential;
import com.linecorp.line.auth.fido.fido2.common.server.VerifyCredential;
import com.linecorp.line.auth.fido.fido2.base.entity.UserKeyEntity;
import com.linecorp.line.auth.fido.fido2.server.model.Session;
import com.linecorp.line.auth.fido.fido2.base.repository.UserKeyRepository;
import com.linecorp.line.auth.fido.fido2.server.service.SessionService;
import com.linecorp.line.auth.fido.fido2.demo.support.restdocs.TestSupportForSpringRestDocs;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.MethodArgumentNotValidException;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Rollback
@Transactional
class ResponseControllerTest extends TestSupportForSpringRestDocs {

    @Autowired
    private UserKeyRepository userKeyRepository;

    @Autowired
    private SessionService sessionService;

    @Test
    void sendRegResponse_success() throws Exception {

        final Session session = sessionService.createSessionData();
        final RegOptionResponse regOptionResponse = objectMapper.readValue(readJson(REG_CHALLENGE_RES_JSON_PATH), RegOptionResponse.class);
        session.setRegOptionResponse(regOptionResponse);
        session.setId(regOptionResponse.getSessionId());
        sessionService.createSession(session);

        final String expectedResult = readJson(REG_RESPONSE_RES_JSON_PATH);

        mockMvc.perform(post(REG_RESPONSE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(readJson(REG_RESPONSE_REQ_JSON_PATH))
                )
                .andExpect(MockMvcResultMatchers.content().json(expectedResult))
                .andExpect(status().isOk());

    }

    @Test
    void sendAuthResponse_success() throws Exception {

        final Session session = sessionService.createSessionData();
        final AuthOptionResponse authOptionResponse = objectMapper.readValue(readJson(AUTH_CHALLENGE_RES_JSON_PATH), AuthOptionResponse.class);
        session.setAuthOptionResponse(authOptionResponse);
        session.setId(authOptionResponse.getSessionId());
        sessionService.createSession(session);

        final UserKeyEntity userKeyEntity = objectMapper.readValue(readJson(DATABASE_USER_KEY_ENTITY_JSON_PATH), UserKeyEntity.class);
        userKeyRepository.save(userKeyEntity);

        final String expectedResult = readJson(AUTH_RESPONSE_RES_JSON_PATH);

        mockMvc.perform(post(AUTH_RESPONSE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(readJson(AUTH_RESPONSE_REQ_JSON_PATH))
                )
                .andExpect(MockMvcResultMatchers.content().json(expectedResult))
                .andExpect(status().isOk());
    }

    @Test
    void validateIncompleteRegRequestShouldReturnMethodArgumentNotValidException() throws Exception {

        final RegisterCredential regResponseRequest = objectMapper.readValue(readJson(REG_RESPONSE_REQ_JSON_PATH), RegisterCredential.class);
        regResponseRequest.setOrigin("");

        mockMvc.perform(MockMvcRequestBuilders.post(REG_RESPONSE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regResponseRequest)))
                .andExpect(result -> assertTrue(result.getResolvedException() instanceof MethodArgumentNotValidException))
                .andExpect(status().isBadRequest());
    }

    @Test
    void validateIncompleteAuthRequestShouldReturnMethodArgumentNotValidException() throws Exception {

        final VerifyCredential authResponseRequest = objectMapper.readValue(readJson(AUTH_RESPONSE_REQ_JSON_PATH), VerifyCredential.class);
        authResponseRequest.setRpId("");

        mockMvc.perform(MockMvcRequestBuilders.post(AUTH_RESPONSE_URL_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authResponseRequest)))
                .andExpect(result -> assertTrue(result.getResolvedException() instanceof MethodArgumentNotValidException))
                .andExpect(status().isBadRequest());
    }
}

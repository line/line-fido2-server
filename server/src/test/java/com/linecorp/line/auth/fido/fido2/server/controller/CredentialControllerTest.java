package com.linecorp.line.auth.fido.fido2.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.linecorp.line.auth.fido.fido2.server.entity.UserKeyEntity;
import com.linecorp.line.auth.fido.fido2.server.repository.UserKeyRepository;
import com.linecorp.line.auth.fido.fido2.server.restdocs.TestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.request.RequestDocumentation.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Rollback
@Transactional
class CredentialControllerTest extends TestSupport {

    @Autowired
    private UserKeyRepository userKeyRepository;

    private UserKeyEntity userKeyEntity;

    @BeforeEach
    void init() throws Exception {
        userKeyEntity = new ObjectMapper().readValue(readJson("/json/database/user-key-entity.json"), UserKeyEntity.class);
        userKeyRepository.save(userKeyEntity);
    }

    @Test
    void getCredentialWithCredentialIdAndRpId() throws Exception {
        mockMvc.perform(get("/fido2/credentials/{id}", userKeyEntity.getCredentialId())
                        .param("rpId", userKeyEntity.getRpEntity().getId())
                )
                .andExpect(status().isOk())
                .andDo(restDocs.document(
                        requestParameters(
                                parameterWithName("rpId").description("RP Id")
                        ),
                        pathParameters(
                                parameterWithName("id").description("credential Id")
                        )
                ));
    }

    @Test
    void getCredentialsWithUserIdAndRpId() throws Exception {
        mockMvc.perform(get("/fido2/credentials")
                        .param("rpId", userKeyEntity.getRpEntity().getId())
                        .param("userId", userKeyEntity.getUserId())
                )
                .andExpect(status().isOk())
                .andDo(restDocs.document(requestParameters(
                        parameterWithName("rpId").description("RP Id"),
                        parameterWithName("userId").description("User Id")
                )));
    }

    @Test
    void deleteCredentialWithCredentialIdAndRpId() throws Exception {
        mockMvc.perform(delete("/fido2/credentials/{id}", userKeyEntity.getCredentialId())
                        .param("rpId", userKeyEntity.getRpEntity().getId())
                )
                .andExpect(status().isOk())
                .andDo(restDocs.document(requestParameters(
                                parameterWithName("rpId").description("RP Id")
                        ),
                        pathParameters(
                                parameterWithName("id").description("credential Id")
                        )));
    }

    @Test
    void deleteCredentialWithUserIdIdAndRpId() throws Exception {
        mockMvc.perform(delete("/fido2/credentials")
                        .param("rpId", userKeyEntity.getRpEntity().getId())
                        .param("userId", userKeyEntity.getUserId())
                )
                .andExpect(status().isOk())
                .andDo(restDocs.document(requestParameters(
                        parameterWithName("rpId").description("RP Id"),
                        parameterWithName("userId").description("User Id")
                )));
    }
}
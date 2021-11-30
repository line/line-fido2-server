package com.linecorp.line.auth.fido.fido2.server.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.linecorp.line.auth.fido.fido2.server.entity.UserKeyEntity;
import com.linecorp.line.auth.fido.fido2.server.repository.UserKeyRepository;
import com.linecorp.line.auth.fido.fido2.server.support.restdocs.TestSupportForSpringRestDocs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.request.RequestDocumentation.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Rollback
@Transactional
class CredentialControllerTest extends TestSupportForSpringRestDocs {

    @Autowired
    private UserKeyRepository userKeyRepository;

    private UserKeyEntity userKeyEntity;

    @BeforeEach
    void init() throws Exception {
        userKeyEntity = new ObjectMapper().readValue(readJson(DATABASE_USER_KEY_ENTITY_JSON_PATH), UserKeyEntity.class);
        userKeyRepository.save(userKeyEntity);
    }

    @Test
    void getCredentialWithCredentialIdAndRpId_success() throws Exception {
        mockMvc.perform(get("/fido2/credentials/{id}", userKeyEntity.getCredentialId())
                        .param("rpId", userKeyEntity.getRpEntity().getId())
                )
                .andExpect(jsonPath("$.credential.id", is(userKeyEntity.getUserId())))
                .andExpect(jsonPath("$.credential.name", is(userKeyEntity.getUsername())))
                .andExpect(jsonPath("$.credential.credentialId", is(userKeyEntity.getCredentialId())))
                .andExpect(jsonPath("$.serverResponse.internalError", is("SUCCESS")))
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
    void getCredentialsWithUserIdAndRpId_success() throws Exception {
        mockMvc.perform(get("/fido2/credentials")
                        .param("rpId", userKeyEntity.getRpEntity().getId())
                        .param("userId", userKeyEntity.getUserId())
                )
                .andExpect(jsonPath("$.credentials", hasSize(1)))
                .andExpect(jsonPath("$.credentials[0].id", is(userKeyEntity.getUserId())))
                .andExpect(jsonPath("$.credentials[0].name", is(userKeyEntity.getUsername())))
                .andExpect(jsonPath("$.credentials[0].credentialId", is(userKeyEntity.getCredentialId())))
                .andExpect(jsonPath("$.serverResponse.internalError", is("SUCCESS")))
                .andExpect(status().isOk())
                .andDo(restDocs.document(requestParameters(
                        parameterWithName("rpId").description("RP Id"),
                        parameterWithName("userId").description("User Id")
                )));
    }

    @Test
    void deleteCredentialWithCredentialIdAndRpId_success() throws Exception {

        final UserKeyEntity userKeyEntityBefore = userKeyRepository.findByRpEntityIdAndCredentialId(userKeyEntity.getRpEntity().getId(), userKeyEntity.getCredentialId());
        assertThat(userKeyEntityBefore).isNotNull();

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

        final UserKeyEntity userKeyEntityAfter = userKeyRepository.findByRpEntityIdAndCredentialId(userKeyEntity.getRpEntity().getId(), userKeyEntity.getCredentialId());
        assertThat(userKeyEntityAfter).isNull();
    }

    @Test
    void deleteCredentialWithUserIdIdAndRpId_success() throws Exception {

        final List<UserKeyEntity> userListBefore = userKeyRepository.findAllByRpEntityIdAndUserId(userKeyEntity.getRpEntity().getId(), userKeyEntity.getUserId());
        assertThat(userListBefore).hasSize(1);

        mockMvc.perform(delete("/fido2/credentials")
                        .param("rpId", userKeyEntity.getRpEntity().getId())
                        .param("userId", userKeyEntity.getUserId())
                )
                .andExpect(status().isOk())
                .andDo(restDocs.document(requestParameters(
                        parameterWithName("rpId").description("RP Id"),
                        parameterWithName("userId").description("User Id")
                )));

        final List<UserKeyEntity> userListAfter = userKeyRepository.findAllByRpEntityIdAndUserId(userKeyEntity.getRpEntity().getId(), userKeyEntity.getUserId());
        assertThat(userListAfter).isEmpty();
    }
}
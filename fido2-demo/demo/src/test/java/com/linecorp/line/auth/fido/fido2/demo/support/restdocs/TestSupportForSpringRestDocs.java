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

package com.linecorp.line.auth.fido.fido2.demo.support.restdocs;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.util.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ResourceLoader;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation;
import org.springframework.restdocs.mockmvc.RestDocumentationResultHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.nio.charset.StandardCharsets;


@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(RestDocumentationExtension.class)
@Import(SpringRestDocsConfiguration.class)
public class TestSupportForSpringRestDocs {

    protected static final String DATABASE_USER_KEY_ENTITY_JSON_PATH = "/json/database/user-key-entity.json";
    protected static final String REG_CHALLENGE_RES_JSON_PATH = "/json/reg/reg-challenge-res.json";
    protected static final String REG_CHALLENGE_REQ_JSON_PATH = "/json/reg/reg-challenge-req.json";
    protected static final String AUTH_CHALLENGE_RES_JSON_PATH = "/json/auth/auth-challenge-res.json";
    protected static final String AUTH_CHALLENGE_REQ_JSON_PATH = "/json/auth/auth-challenge-req.json";

    protected static final String AUTH_RESPONSE_RES_JSON_PATH = "/json/auth/auth-response-res.json";
    protected static final String AUTH_RESPONSE_REQ_JSON_PATH = "/json/auth/auth-response-req.json";
    protected static final String REG_RESPONSE_RES_JSON_PATH = "/json/reg/reg-response-res.json";
    protected static final String REG_RESPONSE_REQ_JSON_PATH = "/json/reg/reg-response-req.json";

    protected static final String REG_CHALLENGE_URL_PATH = "/fido2/reg/challenge";
    protected static final String REG_RESPONSE_URL_PATH = "/fido2/reg/response";
    protected static final String AUTH_CHALLENGE_URL_PATH = "/fido2/auth/challenge";
    protected static final String AUTH_RESPONSE_URL_PATH = "/fido2/auth/response";

    protected MockMvc mockMvc;

    protected final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    protected RestDocumentationResultHandler restDocs;

    @Autowired
    private ResourceLoader resourceLoader;

    @BeforeEach
    void setUp(
            final WebApplicationContext context,
            final RestDocumentationContextProvider provider
    ) {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(MockMvcRestDocumentation.documentationConfiguration(provider))
                .alwaysDo(MockMvcResultHandlers.print())
                .alwaysDo(restDocs)
                .build();
    }

    protected String readJson(final String path) throws IOException {
        return IOUtils.toString(resourceLoader.getResource("classpath:" + path).getInputStream(),
                StandardCharsets.UTF_8);
    }
}

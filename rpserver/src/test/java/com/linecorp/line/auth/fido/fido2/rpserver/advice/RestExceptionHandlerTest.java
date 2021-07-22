/*
 * Copyright 2021 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
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

package com.linecorp.line.auth.fido.fido2.rpserver.advice;

import com.linecorp.line.auth.fido.fido2.rpserver.model.Status;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

import java.nio.charset.Charset;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class RestExceptionHandlerTest {

    private static final String RUNTIME_EXCEPTION_MSG = "Unknown Error";
    private static final String FIDO2_SERVER_RESPONSE_EXCEPTION_MSG = "\"{\\\"serverResponse\\\":{\\\"description\\\":\\\"RP ID not found: test.org\\\",\\\"internalError\\\":\\\"RPID_NOT_FOUND\\\",\\\"internalErrorCode\\\":46,\\\"internalErrorCodeDescription\\\":null}}\"";

    @Autowired
    private RestExceptionHandler exceptionHandler;
    private MockMvc mockMvc;

    @BeforeEach
    void init(){
        mockMvc = MockMvcBuilders.standaloneSetup(new TestController()).setControllerAdvice(exceptionHandler).build();
    }

    @Test
    public void handleException() throws Exception {
        mockMvc.perform(post("/exception"))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(Status.FAILED.getValue()))
                .andExpect(jsonPath("$.errorMessage").value(RUNTIME_EXCEPTION_MSG));
    }

    @Test
    public void handleHttpClientErrorException() throws Exception {
        mockMvc.perform(post("/fido2ServerException"))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(Status.FAILED.getValue()))
                .andExpect(jsonPath("$.errorMessage").value(FIDO2_SERVER_RESPONSE_EXCEPTION_MSG));
    }

    @TestComponent
    @RestController
    class TestController {

        @PostMapping("/exception")
        public void throwRuntimeException() {
            throw new RuntimeException(RUNTIME_EXCEPTION_MSG);
        }

        @PostMapping("/fido2ServerException")
        public void throwFido2ServerException() {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,null,FIDO2_SERVER_RESPONSE_EXCEPTION_MSG.getBytes(), Charset.defaultCharset());
        }
    }
}
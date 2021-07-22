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

package com.linecorp.line.auth.fido.fido2.server.advice;

import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode.INTERNAL_SERVER_ERROR;
import static com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode.INVALID_REQUEST_BODY;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class RestExceptionHandlerTest {

    private static final String FIDO2_SERVER_RUNTIME_EXCEPTION_MSG = "rpId should not be null or empty";
    private static final String RUNTIME_EXCEPTION_MSG = "Unknown Error";
    private static final String FIDO2_U2F_SERVER_RUNTIME_EXCEPTION_MSG = "Not allowed origin";
    @Autowired
    private RestExceptionHandler exceptionHandler;
    private MockMvc mockMvc;

    @BeforeEach
    void init() {
        mockMvc = MockMvcBuilders.standaloneSetup(new TestController()).setControllerAdvice(exceptionHandler).build();
    }

    @Test
    public void handleFIDO2ServerRuntimeException() throws Exception {
        mockMvc.perform(get("/FIDO2ServerRuntimeException"))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.serverResponse.description")
                        .value(FIDO2_SERVER_RUNTIME_EXCEPTION_MSG))
                .andExpect(jsonPath("$.serverResponse.internalError")
                        .value(INVALID_REQUEST_BODY.name()))
                .andExpect(jsonPath("$.serverResponse.internalErrorCode")
                        .value(INVALID_REQUEST_BODY.getCode()));
    }

    @Test
    public void handleRestOfException() throws Exception {
        mockMvc.perform(delete("/otherException"))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.serverResponse.description")
                        .value(RUNTIME_EXCEPTION_MSG))
                .andExpect(jsonPath("$.serverResponse.internalError")
                        .value(INTERNAL_SERVER_ERROR.name()))
                .andExpect(jsonPath("$.serverResponse.internalErrorCode")
                        .value(INTERNAL_SERVER_ERROR.getCode()));
    }

    @TestComponent
    @RestController
    class TestController {

        @GetMapping("/FIDO2ServerRuntimeException")
        public void throwFIDO2ServerRuntimeException() {
            throw new FIDO2ServerRuntimeException(INVALID_REQUEST_BODY, FIDO2_SERVER_RUNTIME_EXCEPTION_MSG);
        }

        @DeleteMapping("/otherException")
        public void throwRuntimeException() {
            throw new RuntimeException(RUNTIME_EXCEPTION_MSG);
        }
    }
}
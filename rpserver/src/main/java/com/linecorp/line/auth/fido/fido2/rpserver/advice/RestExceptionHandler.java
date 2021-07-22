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
import com.linecorp.line.auth.fido.fido2.rpserver.model.transport.AdapterServerResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@Slf4j
@ControllerAdvice
public class RestExceptionHandler extends ResponseEntityExceptionHandler {
    @ExceptionHandler(HttpClientErrorException.class)
    protected ResponseEntity<AdapterServerResponse> handleRestOfException(Exception ex, HttpClientErrorException body, WebRequest request) {
        log.error("Unhandled Exception", ex);
        log.error(ex.getMessage());

        Throwable cause = ex.getCause();
        log.error("Unhandled exception::cause: " + (cause == null ? "<none>" : cause.getMessage()));
        if (cause != null) {
            log.error("cause::stack trace: ", cause);
        }

        AdapterServerResponse serverResponse = new AdapterServerResponse();
        serverResponse.setStatus(Status.FAILED);
        serverResponse.setErrorMessage(body.getResponseBodyAsString());
        return new ResponseEntity<>(serverResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    protected ResponseEntity<AdapterServerResponse> handleRestOfException(Exception ex, WebRequest request) {
        log.error("Unhandled Exception", ex);
        log.error(ex.getMessage());

        Throwable cause = ex.getCause();
        log.error("Unhandled exception::cause: " + (cause == null ? "<none>" : cause.getMessage()));
        if (cause != null) {
            log.error("cause::stack trace: ", cause);
        }

        AdapterServerResponse serverResponse = new AdapterServerResponse();
        serverResponse.setStatus(Status.FAILED);
        serverResponse.setErrorMessage(ex.getMessage());
        return new ResponseEntity<>(serverResponse, HttpStatus.BAD_REQUEST);
    }
}



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

import com.linecorp.line.auth.fido.fido2.common.server.ServerResponse;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.model.FIDOServerErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@Slf4j
@ControllerAdvice
public class RestExceptionHandler extends ResponseEntityExceptionHandler {
    @ExceptionHandler(FIDO2ServerRuntimeException.class)
    protected ResponseEntity<FIDOServerErrorResponse> handleServerRuntimeException(FIDO2ServerRuntimeException ex, WebRequest request) {
        log.error("FIDO2ServerRuntimeException {}({})", ex.getErrorCode(), ex.getErrorCode().getCode());
        log.error(ex.getLocalizedMessage());

        log.error("FIDO2ServerRuntimeException::stack trace:", ex);
        Throwable cause = ex.getCause();
        log.error("FIDO2ServerRuntimeException::cause: " + (cause == null ? "<none>" : cause.getMessage()));
        if (cause != null) {
            log.error("cause::stack trace: ", cause);
        }

        FIDOServerErrorResponse fidoServerErrorResponse = new FIDOServerErrorResponse();
        ServerResponse serverResponse = ServerResponse
                .builder()
                .description(ex.getMessage())
                .internalError(ex.getErrorCode().name())
                .internalErrorCode(ex.getErrorCode().getCode())
                .build();

        fidoServerErrorResponse.setServerResponse(serverResponse);
        return new ResponseEntity<>(fidoServerErrorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    protected ResponseEntity<FIDOServerErrorResponse> handleRestOfException(Exception ex, WebRequest request) {
        log.error("Unhandled Exception", ex);
        log.error(ex.getLocalizedMessage());

        Throwable cause = ex.getCause();
        log.error("Unhandled exception::cause: " + (cause == null ? "<none>" : cause.getMessage()));
        if (cause != null) {
            log.error("cause::stack trace: ", cause);
        }

        InternalErrorCode errorCode = InternalErrorCode.INTERNAL_SERVER_ERROR;
        FIDOServerErrorResponse fidoServerErrorResponse = new FIDOServerErrorResponse();
        ServerResponse serverResponse = ServerResponse
                .builder()
                .description(ex.getMessage())
                .internalError(errorCode.name())
                .internalErrorCode(errorCode.getCode())
                .build();

        fidoServerErrorResponse.setServerResponse(serverResponse);
        return new ResponseEntity<>(fidoServerErrorResponse, HttpStatus.BAD_REQUEST);
    }
}



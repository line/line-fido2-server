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

import com.linecorp.line.auth.fido.fido2.common.server.RegisterCredential;
import com.linecorp.line.auth.fido.fido2.common.server.RegisterCredentialResult;
import com.linecorp.line.auth.fido.fido2.common.server.VerifyCredential;
import com.linecorp.line.auth.fido.fido2.common.server.VerifyCredentialResult;
import com.linecorp.line.auth.fido.fido2.server.service.ResponseService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@Slf4j
@RestController
@RequiredArgsConstructor
public class ResponseController {
    private final ResponseService responseService;

    @PostMapping(path = "fido2/reg/response")
    public RegisterCredentialResult sendRegResponse(@Valid @RequestBody RegisterCredential registerCredential) {
        return responseService.handleAttestation(registerCredential.getServerPublicKeyCredential(), registerCredential.getSessionId(),
                registerCredential.getOrigin(), registerCredential.getRpId(), registerCredential.getTokenBinding());
    }

    @PostMapping(path = "fido2/auth/response")
    public VerifyCredentialResult sendAuthResponse(@Valid @RequestBody VerifyCredential verifyCredential) {
        return responseService.handleAssertion(verifyCredential.getServerPublicKeyCredential(), verifyCredential.getSessionId(),
                verifyCredential.getOrigin(), verifyCredential.getRpId(), verifyCredential.getTokenBinding());
    }
}

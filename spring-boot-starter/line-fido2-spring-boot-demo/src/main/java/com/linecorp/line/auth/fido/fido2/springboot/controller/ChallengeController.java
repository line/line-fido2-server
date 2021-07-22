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

package com.linecorp.line.auth.fido.fido2.springboot.controller;

import com.linecorp.line.auth.fido.fido2.common.server.AuthOptionRequest;
import com.linecorp.line.auth.fido.fido2.common.server.AuthOptionResponse;
import com.linecorp.line.auth.fido.fido2.common.server.RegOptionRequest;
import com.linecorp.line.auth.fido.fido2.common.server.RegOptionResponse;
import com.linecorp.line.auth.fido.fido2.server.service.ChallengeService;
import com.linecorp.line.auth.fido.fido2.server.util.ReqMsgVerifier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class ChallengeController {
    private final ChallengeService challengeService;

    @Autowired
    public ChallengeController(ChallengeService challengeService) {
        this.challengeService = challengeService;
    }

    @PostMapping(path = "fido2/reg/challenge")
    public RegOptionResponse getRegChallenge(@RequestBody RegOptionRequest regOptionRequest) {
        ReqMsgVerifier.validateRegOptionRequest(regOptionRequest);
        return challengeService.getRegChallenge(regOptionRequest);
    }

    @PostMapping(path = "fido2/auth/challenge")
    public AuthOptionResponse getAuthChallenge(@RequestBody AuthOptionRequest authOptionRequest) {
        ReqMsgVerifier.validateAuthOptionRequest(authOptionRequest);
        return challengeService.getAuthChallenge(authOptionRequest);
    }
}

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

package com.linecorp.line.auth.fido.fido2.server.controller;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.linecorp.line.auth.fido.fido2.common.server.BaseResponse;
import com.linecorp.line.auth.fido.fido2.common.server.GetCredentialResult;
import com.linecorp.line.auth.fido.fido2.common.server.GetCredentialsResult;
import com.linecorp.line.auth.fido.fido2.common.server.ServerResponse;
import com.linecorp.line.auth.fido.fido2.common.server.ServerUserKey;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.model.UserKey;
import com.linecorp.line.auth.fido.fido2.server.service.UserKeyService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class CredentialController {
    private final UserKeyService userKeyService;

    @Autowired
    public CredentialController(UserKeyService userKeyService) {
        this.userKeyService = userKeyService;
    }

    @GetMapping(path = "fido2/credentials/{id}")
    public GetCredentialResult getCredentialWithCredentialIdAndRpId(
            @PathVariable("id") String credentialId,
            @RequestParam("rpId") String rpId) {

        return GetCredentialResult
                .builder()
                .serverResponse(ServerResponse.builder()
                                              .internalErrorCode(InternalErrorCode.SUCCESS.getCode())
                                              .internalError(InternalErrorCode.SUCCESS.name())
                                              .build())
                .credential(convert(userKeyService.getWithCredentialId(rpId, credentialId)))
                .build();
    }

    @GetMapping(path = "fido2/credentials")
    public GetCredentialsResult getCredentialsWithUserIdAndRpId(
            @RequestParam("rpId") String rpId,
            @RequestParam("userId") String userId) {

        return GetCredentialsResult
                .builder()
                .serverResponse(ServerResponse.builder()
                                              .internalErrorCode(InternalErrorCode.SUCCESS.getCode())
                                              .internalError(InternalErrorCode.SUCCESS.name())
                                              .build())
                .credentials(convert(userKeyService.getWithUserId(rpId, userId)))
                .build();
    }

    @DeleteMapping(path = "fido2/credentials/{id}")
    public BaseResponse deleteCredentialWithCredentialIdAndRpId(
            @PathVariable("id") String credentialId,
            @RequestParam("rpId") String rpId) {
        userKeyService.deleteWithCredentialId(rpId, credentialId);

        return BaseResponse
                .builder()
                .serverResponse(ServerResponse.builder()
                                              .internalErrorCode(InternalErrorCode.SUCCESS.getCode())
                                              .internalError(InternalErrorCode.SUCCESS.name())
                                              .build())
                .build();
    }

    @DeleteMapping(path = "fido2/credentials")
    public BaseResponse deleteCredentialWithUserIdIdAndRpId(
            @RequestParam("rpId") String rpId,
            @RequestParam("userId") String userId) {
        userKeyService.deleteWithUserId(rpId, userId);

        return BaseResponse
                .builder()
                .serverResponse(ServerResponse.builder()
                                              .internalErrorCode(InternalErrorCode.SUCCESS.getCode())
                                              .internalError(InternalErrorCode.SUCCESS.name())
                                              .build())
                .build();
    }

    private ServerUserKey convert(UserKey userKey) {
        return ServerUserKey
                .builder()
                .aaguid(userKey.getAaguid())
                .algorithm(userKey.getAlgorithm())
                .attestationType(userKey.getAttestationType())
                .credentialId(userKey.getCredentialId())
                .displayName(userKey.getDisplayName())
                .icon(userKey.getIcon())
                .id(userKey.getId())
                .name(userKey.getName())
                .publicKey(Base64.getUrlEncoder().withoutPadding().encodeToString(userKey.getPublicKey().getEncoded()))
                .rpId(userKey.getRpId())
                .signCounter(userKey.getSignCounter())
                .registeredAt(userKey.getRegisteredAt())
                .authenticatedAt(userKey.getAuthenticatedAt())
                .transports(userKey.getTransports())
                .rk(userKey.getRk())
                .credProtect(userKey.getCredProtect())
                .build();
    }

    private List<ServerUserKey> convert(List<UserKey> userKeyList) {
        List<ServerUserKey> serverUserKeys = new ArrayList<>();
        for (UserKey userKey : userKeyList) {
            serverUserKeys.add(convert(userKey));
        }

        return serverUserKeys;
    }
}

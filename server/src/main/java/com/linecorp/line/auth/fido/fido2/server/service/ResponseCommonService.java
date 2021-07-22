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

package com.linecorp.line.auth.fido.fido2.server.service;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;

import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.linecorp.line.auth.fido.fido2.common.TokenBinding;
import com.linecorp.line.auth.fido.fido2.common.crypto.Digests;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.model.CollectedClientData;

import lombok.extern.slf4j.Slf4j;

@Slf4j
abstract public class ResponseCommonService {

    protected abstract void checkOrigin(URI originFromClientData, URI originFromRp);

    /**
     * Process common part of reg/auth operations
     * Refer followings:
     *  - https://www.w3.org/TR/2018/CR-webauthn-20180807/#registering-a-new-credential
     *  - https://www.w3.org/TR/2018/CR-webauthn-20180807/#verifying-assertion
     * @param type
     * @param challengeSent
     * @param base64UrlEncodedClientDataJSON
     * @param origin
     * @param tokenBinding
     * @return
     */
    public byte[] handleCommon(String type, String challengeSent, String base64UrlEncodedClientDataJSON, String origin, TokenBinding tokenBinding) {
        String clientDataJSON = new String(Base64.getUrlDecoder().decode(base64UrlEncodedClientDataJSON));
        log.info("clientDataJSON: {}", clientDataJSON);
        CollectedClientData collectedClientData;
        try {
            collectedClientData = getCollectedClientData(clientDataJSON);
        } catch (IOException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_FORMAT_CLIENT_DATA_JSON, e);
        }
        byte[] clientDataJSONBytes = clientDataJSON.getBytes();

        log.info("collectedClientData: {}", collectedClientData);
        // verify collected client data
        if (StringUtils.isEmpty(collectedClientData.getType()) ||
                StringUtils.isEmpty(collectedClientData.getChallenge()) ||
                StringUtils.isEmpty(collectedClientData.getOrigin())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_FORMAT_CLIENT_DATA_JSON, "Required field missing");
        }

        // verify challenge (should be matched to challenge sent in create call)
        log.info("Verify challenge matched to challenge sent");
        if (!collectedClientData.getChallenge().equals(challengeSent)) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.CHALLENGE_NOT_MATCHED);
        }

        // verify type
        log.info("Check operation type in collectedClientData");
        if (!type.equals(collectedClientData.getType())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_OPERATION_TYPE);
        }

        // verify origin
        log.info("Verify origin matched to origin in collectedClientData");
        URI originFromClientData;
        URI originFromRp;
        try {
            originFromClientData = new URI(collectedClientData.getOrigin());
            originFromRp = new URI(origin);
        } catch (URISyntaxException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_ORIGIN, e);
        }

        checkOrigin(originFromClientData, originFromRp);

        // verify token binding
        log.info("Verify token binding if supported");
        if (collectedClientData.getTokenBinding() != null) {
            if (collectedClientData.getTokenBinding().getStatus() == null) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.TOKEN_BINDING_STATUS_MISSING);
            }
            if (tokenBinding != null) {
                if (collectedClientData.getTokenBinding().getStatus() != tokenBinding.getStatus()) {
                    throw new FIDO2ServerRuntimeException(InternalErrorCode.TOKEN_BINDING_INFO_NOT_MATCHED);
                } else {
                    if (collectedClientData.getTokenBinding().getId() == null ||
                            tokenBinding.getId() == null) {
                        throw new FIDO2ServerRuntimeException(InternalErrorCode.TOKEN_BINDING_INFO_NOT_MATCHED);
                    } else {
                        if (!tokenBinding.getId().equals(collectedClientData.getTokenBinding().getId())) {
                            throw new FIDO2ServerRuntimeException(InternalErrorCode.TOKEN_BINDING_INFO_NOT_MATCHED);
                        }
                    }
                }
            }
        }

        // compute hash of clientDataJSON
        log.info("Compute hash of clientDataJSON");

        return Digests.sha256(clientDataJSONBytes);
    }

    private CollectedClientData getCollectedClientData(String clientDataJSON) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(clientDataJSON, CollectedClientData.class);
    }
}

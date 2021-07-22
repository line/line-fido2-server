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

package com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import okhttp3.ResponseBody;
import retrofit2.Response;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

public class AdditionalRevokeChecker {
    public static boolean hasAndroidKeyAttestationRevokedCert(RevokeCheckerClient client, List<Certificate> trustPath) throws IOException {

        Response<ResponseBody> bodyResponse = client.fetchAndroidKeyAttestationRevokeList("attestation/status");

        if (bodyResponse.isSuccessful()) {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode node;
            if (bodyResponse.body() != null) {
                node = objectMapper.readTree(bodyResponse.body().string()).get("entries");
            } else {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_KEY_ATTESTATION_CERTIFICATE_REVOKED_CHECK_FAILED);
            }
            return trustPath.stream().anyMatch(certificate -> {
                X509Certificate cert = (X509Certificate) certificate;
                String serialNum = cert.getSerialNumber().toString(16).toLowerCase();
                return node.has(serialNum);
            });
        } else {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_KEY_ATTESTATION_CERTIFICATE_REVOKED_CHECK_FAILED);
        }
    }
}

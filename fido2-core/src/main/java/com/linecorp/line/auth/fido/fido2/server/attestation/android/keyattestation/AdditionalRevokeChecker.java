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

package com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation;

import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import retrofit2.Response;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

public class AdditionalRevokeChecker {

    public static void checkAndroidKeyAttestationRevokedCert(RevokeCheckerClient client, List<Certificate> trustPath) {
        if (trustPath == null || trustPath.isEmpty()) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_KEY_ATTESTATION_CERTIFICATE_REVOKED_CHECK_FAILED, "Trust path is null or empty.");
        }

        Response<RevokedEntries> response = client.fetchAndroidKeyAttestationRevokeList("attestation/status");

        if (!response.isSuccessful() || response.body() == null || response.body().getEntries() == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_KEY_ATTESTATION_CERTIFICATE_REVOKED_CHECK_FAILED, "Failed to fetch revoke list or revoked entries is null.");
        }

        RevokedEntries revokedEntries = response.body();

        trustPath.forEach(certificate -> {
            X509Certificate cert = (X509Certificate) certificate;
            String serialNum = cert.getSerialNumber().toString(16).toLowerCase();
            if (revokedEntries.getEntries().containsKey(serialNum)) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.ANDROID_KEY_ATTESTATION_CERTIFICATE_REVOKED_CHECK_FAILED, "Certificate is revoked: " + serialNum);
            }
        });
    }
}

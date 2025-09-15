/*
 * Copyright 2025 LY Corporation
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

package com.linecorp.line.auth.fido.fido2.server.helper;

import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;

import java.net.URI;
import java.util.List;

/**
 * Helper for origin validation logic. Keeps ResponseServiceImpl readable
 * while preserving exact string-match policy and error messages.
 */
public class OriginValidationHelper {

    private static final String ANDROID_FACET_SCHEME = "android";
    private static final String IOS_FACET_SCHEME = "ios";

    public static boolean isAppFacet(URI origin) {
        String scheme = origin.getScheme();
        return ANDROID_FACET_SCHEME.equals(scheme) || IOS_FACET_SCHEME.equals(scheme);
    }

    public static void validateAppFacet(URI client, List<String> allowed) {
        if (!allowed.contains(client.toString())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ORIGIN_NOT_MATCHED,
                    "Client facet origin: " + client + ", App Origin List: " + allowed);
        }
    }

    public static void validateWeb(URI client, URI rp, List<String> allowed) {
        if (hasWebAllowlist(allowed)) {
            if (!allowed.contains(client.toString())) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.ORIGIN_NOT_MATCHED,
                        "Client web origin: " + client + ", Allowed origins: " + allowed);
            }
            return;
        }

        if (!rp.toString().equals(client.toString())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ORIGIN_NOT_MATCHED,
                    "From collected data: " + client + ", From request param: " + rp);
        }
    }

    private static boolean hasWebAllowlist(List<String> allowed) {
        for (String o : allowed) {
            if (o.startsWith("https://") || o.startsWith("http://")) {
                return true;
            }
        }
        return false;
    }
}

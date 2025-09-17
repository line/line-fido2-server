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

package com.linecorp.line.auth.fido.fido2.server.service;

import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;

import java.net.URI;
import java.util.Collections;
import java.util.List;

public class OriginValidationServiceImpl implements OriginValidationService {

    private static final String ANDROID_FACET_SCHEME = "android";
    private static final String IOS_FACET_SCHEME = "ios";

    private final OriginService originService;

    public OriginValidationServiceImpl(OriginService originService) {
        this.originService = originService;
    }

    @Override
    public void validate(URI originFromClientData, URI originFromRp, String rpId) {
        List<String> allowed = originService.getOrigins(rpId);
        if (allowed == null) {
            allowed = Collections.emptyList();
        }

        if (isAppFacet(originFromClientData)) {
            validateAppFacet(originFromClientData, allowed);
            return;
        }

        validateWeb(originFromClientData, originFromRp, allowed);
    }

    private static boolean isAppFacet(URI origin) {
        String scheme = origin.getScheme();
        return ANDROID_FACET_SCHEME.equals(scheme) || IOS_FACET_SCHEME.equals(scheme);
    }

    private static void validateAppFacet(URI originFromClient, List<String> allowed) {
        if (!allowed.contains(originFromClient.toString())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ORIGIN_NOT_MATCHED,
                    "Client facet origin: " + originFromClient);
        }
    }

    private static void validateWeb(URI originFromClient, URI originFromRp, List<String> allowed) {
        if (hasWebAllowlist(allowed)) {
            if (!allowed.contains(originFromClient.toString())) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.ORIGIN_NOT_MATCHED,
                        "Client web origin: " + originFromClient);
            }
            return;
        }

        if (!originFromRp.toString().equals(originFromClient.toString())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ORIGIN_NOT_MATCHED,
                    "From collected data: " + originFromClient + ", From request param: " + originFromRp);
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

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
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OriginValidationServiceImplTest {

    private OriginValidationService serviceWith(List<String> origins) {
        OriginService originService = new OriginService() {
            @Override
            public List<String> getOrigins(String rpId) {
                return origins;
            }
        };
        return new OriginValidationServiceImpl(originService);
    }

    @Test
    void appFacet_passesWhenAllowedContainsClientOrigin() {
        OriginValidationService service = serviceWith(Arrays.asList("android:aaa-bbb", "ios:ccc-ddd"));
        assertDoesNotThrow(() -> service.validate(URI.create("android:aaa-bbb"), URI.create("https://rp.example.com"), "rp.example.com"));
    }

    @Test
    void appFacet_throwsWhenNotAllowed() {
        OriginValidationService service = serviceWith(Collections.singletonList("android:aaa-bbb"));
        FIDO2ServerRuntimeException ex = assertThrows(FIDO2ServerRuntimeException.class,
                () -> service.validate(URI.create("android:zzz-yyy"), URI.create("https://rp.example.com"), "rp.example.com"));
        assertEquals(InternalErrorCode.ORIGIN_NOT_MATCHED, ex.getErrorCode());
    }

    @Test
    void webAllowlist_passesWhenIncluded() {
        OriginValidationService service = serviceWith(Arrays.asList("android:aaa-bbb", "https://example.com", "ios:ccc-ddd"));
        assertDoesNotThrow(() -> service.validate(URI.create("https://example.com"), URI.create("https://rp.example.com"), "rp.example.com"));
    }

    @Test
    void webAllowlist_failsWhenNotIncluded() {
        OriginValidationService service = serviceWith(Arrays.asList("android:aaa-bbb", "https://example.com"));
        FIDO2ServerRuntimeException ex = assertThrows(FIDO2ServerRuntimeException.class,
                () -> service.validate(URI.create("https://evil.com"), URI.create("https://rp.example.com"), "rp.example.com"));
        assertEquals(InternalErrorCode.ORIGIN_NOT_MATCHED, ex.getErrorCode());
    }

    @Test
    void fallbackStrictEquality_passesOnExactMatch() {
        OriginValidationService service = serviceWith(Arrays.asList("android:aaa-bbb", "ios:ccc-ddd"));
        assertDoesNotThrow(() -> service.validate(URI.create("https://rp.example.com"), URI.create("https://rp.example.com"), "rp.example.com"));
    }

    @Test
    void fallbackStrictEquality_failsOnMismatch() {
        OriginValidationService service = serviceWith(Collections.emptyList());
        FIDO2ServerRuntimeException ex = assertThrows(FIDO2ServerRuntimeException.class,
                () -> service.validate(URI.create("https://rp.example.com"), URI.create("https://another.example.com"), "rp.example.com"));
        assertEquals(InternalErrorCode.ORIGIN_NOT_MATCHED, ex.getErrorCode());
    }
}

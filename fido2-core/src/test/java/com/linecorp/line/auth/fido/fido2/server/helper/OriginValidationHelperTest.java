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
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OriginValidationHelperTest {

    @Test
    void isAppFacet_returnsTrueForAndroidAndIos() {
        assertTrue(OriginValidationHelper.isAppFacet(URI.create("android:aaa-bbb")));
        assertTrue(OriginValidationHelper.isAppFacet(URI.create("ios:aaa-bbb")));
        assertFalse(OriginValidationHelper.isAppFacet(URI.create("https://example.com")));
    }

    @Test
    void validateAppFacet_passesWhenAllowedContainsClientOrigin() {
        List<String> allowed = Arrays.asList("android:aaa-bbb", "ios:ccc-ddd");
        assertDoesNotThrow(() -> OriginValidationHelper.validateAppFacet(URI.create("android:aaa-bbb"), allowed));
    }

    @Test
    void validateAppFacet_throwsWhenNotAllowed() {
        List<String> allowed = Collections.singletonList("android:aaa-bbb");
        FIDO2ServerRuntimeException ex = assertThrows(FIDO2ServerRuntimeException.class,
                () -> OriginValidationHelper.validateAppFacet(URI.create("android:zzz-yyy"), allowed));
        assertEquals(InternalErrorCode.ORIGIN_NOT_MATCHED, ex.getErrorCode());
    }

    @Test
    void validateWeb_usesAllowlistWhenHttpsOriginsConfigured_passes() {
        List<String> allowed = Arrays.asList(
                "android:aaa-bbb",
                "https://example.com",
                "ios:ccc-ddd");
        URI client = URI.create("https://example.com");
        URI rp = URI.create("https://rp.example.com");

        assertDoesNotThrow(() -> OriginValidationHelper.validateWeb(client, rp, allowed));
    }

    @Test
    void validateWeb_usesAllowlistWhenHttpsOriginsConfigured_failsIfNotIncluded() {
        List<String> allowed = Arrays.asList("android:aaa-bbb", "https://example.com");
        URI client = URI.create("https://evil.com");
        URI rp = URI.create("https://rp.example.com");

        FIDO2ServerRuntimeException ex = assertThrows(FIDO2ServerRuntimeException.class,
                () -> OriginValidationHelper.validateWeb(client, rp, allowed));
        assertEquals(InternalErrorCode.ORIGIN_NOT_MATCHED, ex.getErrorCode());
    }

    @Test
    void validateWeb_strictEqualityWhenNoHttpsAllowlist_passes() {
        List<String> allowed = Arrays.asList("android:aaa-bbb", "ios:ccc-ddd");
        URI client = URI.create("https://rp.example.com");
        URI rp = URI.create("https://rp.example.com");

        assertDoesNotThrow(() -> OriginValidationHelper.validateWeb(client, rp, allowed));
    }

    @Test
    void validateWeb_strictEqualityWhenNoHttpsAllowlist_failsOnMismatch() {
        List<String> allowed = Collections.emptyList();
        URI client = URI.create("https://rp.example.com");
        URI rp = URI.create("https://another.example.com");

        FIDO2ServerRuntimeException ex = assertThrows(FIDO2ServerRuntimeException.class,
                () -> OriginValidationHelper.validateWeb(client, rp, allowed));
        assertEquals(InternalErrorCode.ORIGIN_NOT_MATCHED, ex.getErrorCode());
    }
}


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

package com.linecorp.line.auth.fido.fido2.server.attestation.tpm;

import java.util.Arrays;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum TpmSt {
    RSP_COMMAND(0x00C4),
    NULL(0x8000),
    NO_SESSION(0x8001),
    SESSIONS(0x8002),
    ATTEST_NV(0x8014),
    ATTEST_COMMAND_AUDIT(0x8015),
    ATTEST_SESSION_AUDIT(0x8016),
    ATTEST_CERTIFY(0x8017),
    ATTEST_QUOTE(0x8018),
    ATTEST_TIME(0x8019),
    ATTEST_CREATION(0x801A),
    CREATION(0x8021),
    VERIFIED(0x8022),
    AUTH_SECRET(0x8023),
    HASHCHECK(0x8024),
    AUTH_SIGNED(0x8025),
    FU_MANIFEST(0x8029);

    @Getter private final int value;

    public static TpmSt fromValue(int value) {
        return Arrays.stream(TpmSt.values())
                .filter(e -> e.value == value)
                .findFirst()
                .get();
    }
}

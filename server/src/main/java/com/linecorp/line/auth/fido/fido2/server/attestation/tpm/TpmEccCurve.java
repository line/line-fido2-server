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
public enum TpmEccCurve {
    NONE(0x0000),
    NIST_P192(0x0001),
    NIST_P224(0x0002),
    NIST_P256(0x0003),
    NIST_P348(0x0004),
    NIST_P521(0x0005),
    BN_P256(0x0010),
    BN_P638(0x0011),
    SM2_P256(0x0020);

    @Getter private final int value;

    public static TpmEccCurve fromValue(int value) {
        return Arrays.stream(TpmEccCurve.values())
                .filter(e -> e.value == value)
                .findFirst()
                .get();
    }
}

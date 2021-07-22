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
public enum TpmHashAlgorithm {
    SHA1(0x0004),
    SHA256(0x000B),
    SHA384(0x000C),
    SHA512(0x000D),
    SM3_256(0x0012);

    @Getter private final int value;

    public static TpmHashAlgorithm fromValue(int value) {
        return Arrays.stream(TpmHashAlgorithm.values())
                .filter(e -> e.value == value)
                .findFirst()
                .get();
    }

    public String getAlgorithmName() {
        if (value == SHA1.value) {
            return "SHA-1";
        } else if (value == SHA256.value) {
            return "SHA-256";
        } else if (value == SHA384.value) {
            return "SHA-384";
        } else if (value == SHA512.value) {
            return "SHA-512";
        } else {
            return "SM3";
        }
    }
}

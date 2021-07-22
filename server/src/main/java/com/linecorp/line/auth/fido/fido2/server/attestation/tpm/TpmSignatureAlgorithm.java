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
public enum TpmSignatureAlgorithm {
    NULL(0x0010),
    RSASSA(0x0014),
    RSAPSS(0x0016),
    ECDSA(0x0018),
    SM2(0x001B),
    ECSCHNORR(0x001C);

    @Getter private final int value;

    public static TpmSignatureAlgorithm fromValue(int value) {
        return Arrays.stream(TpmSignatureAlgorithm.values())
                     .filter(e -> e.value == value)
                     .findFirst()
                     .get();
    }
}

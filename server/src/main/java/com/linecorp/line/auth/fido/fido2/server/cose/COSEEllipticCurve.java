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

package com.linecorp.line.auth.fido.fido2.server.cose;

import java.util.Arrays;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum COSEEllipticCurve {
    P256("P-256", 1, COSEKeyType.EC2, "secp256r1", "NIST P-256 also known as secp256r1", true),
    P384("P-384", 2, COSEKeyType.EC2, "secp384r1", "NIST P-384 also known as secp384r1", true),
    P521("P-521", 3, COSEKeyType.EC2, "secp521r1", "NIST P-521 also known as secp521r1", true),
    P256K("P-256K", 8, COSEKeyType.EC2, "secp256k1", "SECG secp256k1 curve", false),
    ED25519("Ed25519", 6, COSEKeyType.OKP, "ed25519", "Ed25519 for use w/ EdDSA only", true);

    private final String name;
    private final int value;
    private final COSEKeyType keyType;
    private final String namedCurve;
    private final String description;
    private final boolean recommended;

    public static COSEEllipticCurve fromValue(int value) {
        return Arrays.stream(COSEEllipticCurve.values())
                .filter(e -> e.value == value)
                .findFirst()
                .get();
    }
}

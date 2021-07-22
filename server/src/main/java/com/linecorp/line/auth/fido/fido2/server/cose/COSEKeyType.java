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
public enum COSEKeyType {
    OKP("OKP", 1, "Octet Key Pair"),
    EC2("EC2", 2, "Elliptic Curve Keys w/ x- and y-coordinate pair"),
    RSA("RSA", 3, "RSA Key"),
    SYMMETRIC("Symmetric", 4, "Symmetric Keys");

    private final String name;
    private final int value;
    private final String description;

    public static COSEKeyType fromValue(int value) {
        return Arrays.stream(COSEKeyType.values())
              .filter(e -> e.value == value)
              .findFirst()
              .get();
    }
}

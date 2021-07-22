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

package com.linecorp.line.auth.fido.fido2.server.model;

import java.util.Arrays;

import com.fasterxml.jackson.annotation.JsonValue;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum AttestationStatementFormatIdentifier {
    PACKED("packed"),
    TPM("tpm"),
    ANDROID_KEY("android-key"),
    ANDROID_SAFETYNET("android-safetynet"),
    FIDO_U2F("fido-u2f"),
    NONE("none"),
    APPLE_ANONYMOUS("apple");

    @JsonValue @Getter private final String value;

    public static AttestationStatementFormatIdentifier fromValue(String value){
        return Arrays.stream(AttestationStatementFormatIdentifier.values())
              .filter(e -> e.value.equals(value))
              .findFirst()
              .get();
    }
}

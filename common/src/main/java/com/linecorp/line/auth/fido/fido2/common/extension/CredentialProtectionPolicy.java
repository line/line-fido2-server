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

package com.linecorp.line.auth.fido.fido2.common.extension;

import java.util.Arrays;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum CredentialProtectionPolicy {
    USER_VERIFICATION_OPTIONAL(0x01, "userVerificationOptional"),
    USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST(0x02, "userVerificationOptionalWithCredentialIDList"),
    USER_VERIFICATION_REQUIRED(0x03, "userVerificationRequired");

    @Getter private final int value;
    @Getter @JsonValue private final String stringValue;

    @JsonCreator(mode=JsonCreator.Mode.DELEGATING)
    public static CredentialProtectionPolicy fromStringValue(@JsonProperty("stringValue") String stringValue){
        return Arrays.stream(CredentialProtectionPolicy.values())
                     .filter(e -> e.stringValue.equals(stringValue))
                     .findFirst()
                     .get();
    }

    public static CredentialProtectionPolicy fromValue(int value){
        return Arrays.stream(CredentialProtectionPolicy.values())
                     .filter(e -> e.value == value)
                     .findFirst()
                     .get();
    }
}

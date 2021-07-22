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

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum UserVerificationMethod {
    PRESENCE(0x00000001L),
    FINGERPRINT(0x00000002L),
    PASSCODE(0x00000004L),
    VOICEPRINT(0x00000008L),
    FACEPRINT(0x00000010L),
    LOCATION(0x00000020L),
    EYEPRINT(0x00000040L),
    PATTERN(0x00000080L),
    HANDPRINT(0x00000100L),
    NONE(0x00000200L),
    ALL(0x00000400L);

    @Getter private final long value;

    @JsonCreator(mode=JsonCreator.Mode.DELEGATING)
    public static UserVerificationMethod fromValue(long value){
        return Arrays.stream(UserVerificationMethod.values())
                     .filter(e -> e.value == value)
                     .findFirst()
                     .get();
    }
}

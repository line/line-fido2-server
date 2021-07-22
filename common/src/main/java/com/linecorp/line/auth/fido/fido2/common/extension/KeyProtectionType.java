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
public enum KeyProtectionType {
    SOFTWARE(0x0001),
    HARDWARE(0x0002),
    TEE(0x0004),
    SECURE_ELEMENT(0x0008),
    REMOTE_HANDLE(0x0010);

    @Getter private final int value;

    @JsonCreator(mode=JsonCreator.Mode.DELEGATING)
    public static KeyProtectionType fromValue(int value){
        return Arrays.stream(KeyProtectionType.values())
                     .filter(e -> e.value == value)
                     .findFirst()
                     .get();
    }
}

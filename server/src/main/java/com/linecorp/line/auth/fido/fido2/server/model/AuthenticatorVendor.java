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

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum AuthenticatorVendor {
    YUBICO("yubico"),
    GOOGLE("google"),
    MICROSOFT("microsoft"),
    FEITIAN("feitian"),
    APPLE("apple");

    @Getter private final String value;

    public static AuthenticatorVendor fromValue(String value){
        return Arrays.stream(AuthenticatorVendor.values())
                     .filter(e -> e.value.equals(value.toLowerCase()))
                     .findFirst()
                     .get();
    }

}

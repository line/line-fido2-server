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

package com.linecorp.line.auth.fido.fido2.server.util;

import java.security.SecureRandom;
import java.util.Base64;

public class ChallengeGenerator {
    public static String generate(int byteSize) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] challengeBytes = new byte[byteSize];
        secureRandom.nextBytes(challengeBytes);

        //base 64 url encoding
        return Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);
    }
}

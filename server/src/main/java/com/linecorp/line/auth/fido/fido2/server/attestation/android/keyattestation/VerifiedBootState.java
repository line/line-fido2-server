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

package com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation;

import java.util.Arrays;

public enum VerifiedBootState {
    VERIFIED(0), SELF_SIGNED(1), UNVERIFIED(2), FAILED(3);

    private final int value;

    VerifiedBootState(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static VerifiedBootState fromValue(int value) {
        return Arrays.stream(VerifiedBootState.values())
                .filter(e -> e.value == value)
                .findFirst()
                .get();
    }
}

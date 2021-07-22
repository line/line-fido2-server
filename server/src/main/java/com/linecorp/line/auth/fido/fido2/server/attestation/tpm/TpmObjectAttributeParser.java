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

public class TpmObjectAttributeParser {
    public static final int FIXED_TPM = 1 << 1;
    public static final int ST_CLEAR = 1 << 2;
    public static final int FIXED_PARENT = 1 << 4;
    public static final int SENSITIVE_DATA_ORIGIN = 1 << 5;
    public static final int USER_WITH_AUTH = 1 << 6;
    public static final int ADMIN_WITH_POLICY = 1 << 7;
    public static final int NO_DA = 1 << 10;
    public static final int ENCRYPTED_DUPLICATION = 1 << 11;
    public static final int RESTRICTED = 1 << 16;
    public static final int DECRYPT = 1 << 17;
    public static final int SIGN_ENCRYPT = 1 << 18;

    public static boolean fixedTPM(int flags) {
        return (flags & FIXED_TPM) == FIXED_TPM;
    }

    public static boolean stClear(int flags) {
        return (flags & ST_CLEAR) == ST_CLEAR;
    }

    public static boolean fixedParent(int flags) {
        return (flags & FIXED_PARENT) == FIXED_PARENT;
    }

    public static boolean sensitiveDataOrigin(int flags) {
        return (flags & SENSITIVE_DATA_ORIGIN) == SENSITIVE_DATA_ORIGIN;
    }

    public static boolean userWithAuth(int flags) {
        return (flags & USER_WITH_AUTH) == USER_WITH_AUTH;
    }

    public static boolean adminWithPolicy(int flags) {
        return (flags & ADMIN_WITH_POLICY) == ADMIN_WITH_POLICY;
    }

    public static boolean noDA(int flags) {
        return (flags & NO_DA) == NO_DA;
    }

    public static boolean encryptedDuplication(int flags) {
        return (flags & ENCRYPTED_DUPLICATION) == ENCRYPTED_DUPLICATION;
    }

    public static boolean restricted(int flags) {
        return (flags & RESTRICTED) == RESTRICTED;
    }

    public static boolean decrypt(int flags) {
        return (flags & DECRYPT) == DECRYPT;
    }

    public static boolean signEncrypt(int flags) {
        return (flags & SIGN_ENCRYPT) == SIGN_ENCRYPT;
    }
}

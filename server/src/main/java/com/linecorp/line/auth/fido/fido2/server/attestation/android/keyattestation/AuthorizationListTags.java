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

public class AuthorizationListTags {
    public static final int KM_TAG_PURPOSE = 1;
    public static final int KM_TAG_ALGORITHM = 2;
    public static final int KM_TAG_KEY_SIZE = 3;
    public static final int KM_TAG_DIGEST = 5;
    public static final int KM_TAG_PADDING = 6;
    public static final int KM_TAG_EC_CURVE = 10;
    public static final int KM_TAG_RSA_PUBLIC_EXPONENT = 200;
    public static final int KM_TAG_ACTIVE_DATETIME = 400;
    public static final int KM_TAG_ORIGINATION_EXPIRE_DATETIME = 401;
    public static final int KM_TAG_USAGE_EXPIRE_DATETIME = 402;
    public static final int KM_TAG_NO_AUTH_REQUIRED = 503;
    public static final int KM_TAG_USER_AUTH_TYPE = 504;
    public static final int KM_TAG_AUTH_TIMEOUT = 505;
    public static final int KM_TAG_ALLOW_WHILE_ON_BODY = 506;
    public static final int KM_TAG_ALL_APPLICATIONS = 600;
    public static final int KM_TAG_APPLICATION_ID = 601;
    public static final int KM_TAG_CREATION_DATETIME = 701;
    public static final int KM_TAG_ORIGIN = 702;
    public static final int KM_TAG_ROLLBACK_RESISTANT = 703;
    public static final int KM_TAG_ROOT_OF_TRUST = 704;
    public static final int KM_TAG_OS_VERSION = 705;
    public static final int KM_TAG_PATCHLEVEL = 706;
    public static final int KM_TAG_ATTESTATION_CHALLENGE = 708;
    public static final int KM_TAG_ATTESTATION_APPLICATION_ID = 709;
}

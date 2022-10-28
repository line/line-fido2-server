/*
 * Copyright (c) 2018 LINE Corporation. All rights reserved.
 * LINE Corporation PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.linecorp.line.auth.fido.fido2.common.mdsv3;

public enum AuthenticatorStatus {
    NOT_FIDO_CERTIFIED,
    FIDO_CERTIFIED,
    USER_VERIFICATION_BYPASS,
    ATTESTATION_KEY_COMPROMISE,
    USER_KEY_REMOTE_COMPROMISE,
    USER_KEY_PHYSICAL_COMPROMISE,
    UPDATE_AVAILABLE,
    REVOKED,
    SELF_ASSERTION_SUBMITTED,
    FIDO_CERTIFIED_L1,
    FIDO_CERTIFIED_L1plus,
    FIDO_CERTIFIED_L2,
    FIDO_CERTIFIED_L2plus,
    FIDO_CERTIFIED_L3,
    FIDO_CERTIFIED_L3plus
}

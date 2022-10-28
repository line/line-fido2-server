/*
 * Copyright (c) 2018 LINE Corporation. All rights reserved.
 * LINE Corporation PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata;

public enum AttestationType {
    BASIC_FULL(0x3E07), BASIC_SURROGATE(0x3E08), ECDAA(0x3E09), UNKNOWN(0x9999);

    final public int value;

    AttestationType(int value){
        this.value = value;
    }

    public static AttestationType get(int value){
        for (AttestationType type : AttestationType.values()) {
            if (type.value == value){
                return type;
            }
        }
        return UNKNOWN;
    }
}

/*
 * Copyright (c) 2018 LINE Corporation. All rights reserved.
 * LINE Corporation PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata;

import lombok.Data;

@Data
public class EcdaaTrustAnchor {
    private String X;
    private String Y;
    private String c;
    private String sx;
    private String sy;
    private String G1Curve;
}

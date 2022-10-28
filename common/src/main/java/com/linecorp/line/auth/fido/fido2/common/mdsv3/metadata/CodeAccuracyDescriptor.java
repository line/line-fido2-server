/*
 * Copyright (c) 2018 LINE Corporation. All rights reserved.
 * LINE Corporation PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CodeAccuracyDescriptor {
    private int base;
    private int minLength;
    private Integer maxRetries;
    private Integer blockSlowdown;
}

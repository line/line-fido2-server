/*
 * Copyright (c) 2018 LINE Corporation. All rights reserved.
 * LINE Corporation PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata;

import lombok.Data;

@Data
public class DisplayPNGCharacteristicsDescriptor {
    private long width; //unsigned long
    private long height;    //unsigned long
    private int bitDepth;
    private int colorType;
    private int compression;
    private int filter;
    private int interlace;
    private RgbPaletteEntry[] plte;
}

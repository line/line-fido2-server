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

import java.nio.ByteBuffer;
import java.util.Arrays;

public class UnsignedUtil {
    public static int readUINT16BE(byte[] input) {
        return ((input[0] & 0xFF) << 8) |
               (input[1] & 0xFF);
    }

    public static long readUINT32BE(byte[] input) {
        return ((input[0] & 0xFFL) << 24) |
               ((input[1] & 0xFFL) << 16) |
               ((input[2] & 0xFFL) << 8) |
               (input[3] & 0xFFL);
    }

    public static byte[] writeUINT32BE(long input) {
        byte[] bytes = new byte[8];
        ByteBuffer.wrap(bytes).putLong(input);

        return Arrays.copyOfRange(bytes, 4, 8);
    }
}

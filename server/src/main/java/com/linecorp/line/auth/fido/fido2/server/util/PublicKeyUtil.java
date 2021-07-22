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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class PublicKeyUtil {
    public static PublicKey getRSAPublicKey(byte[] n, byte[] e)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger bigN = new BigInteger(1, n);
        BigInteger bigE = new BigInteger(1, e);
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(bigN, bigE);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(pubKeySpec);
    }

    public static PublicKey getECDSAPublicKey(byte[] x, byte[] y, String namedCurve) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(namedCurve);
        ECNamedCurveSpec params = new ECNamedCurveSpec(namedCurve, spec.getCurve(), spec.getG(), spec.getN());

        // get EC point
        BigInteger xBig = new BigInteger(1, x);
        BigInteger yBig = new BigInteger(1, y);
        ECPoint point = new ECPoint(xBig, yBig);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        return keyFactory.generatePublic(pubKeySpec);
    }

    public static PublicKey getECDHPublicKey(byte[] raw, String namedCurve) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(namedCurve);
        ECNamedCurveSpec params = new ECNamedCurveSpec(namedCurve, spec.getCurve(), spec.getG(), spec.getN());

        // get EC point
        ECPoint point = ECPointUtil.decodePoint(params.getCurve(), raw);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH");
        return keyFactory.generatePublic(pubKeySpec);
    }
    public static PublicKey getEdDSAPublicKey(byte[] x, String namedCurve) throws NoSuchAlgorithmException, InvalidKeySpecException {
        EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName(namedCurve);

        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(x, spec);
        KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
        return keyFactory.generatePublic(pubKeySpec);
    }

    /**
     * Get uncompressed version of ECDSA raw key
     * @param ecPublicKey
     * @return
     * @throws IOException
     */
    public static byte[] getECDSARawPublicKey(ECPublicKey ecPublicKey) throws IOException {
        byte[] raw;
        ByteArrayOutputStream bos = new ByteArrayOutputStream(65);

        bos.write(0x04);
        bos.write(asUnsignedByteArray(ecPublicKey.getW().getAffineX()));
        bos.write(asUnsignedByteArray(ecPublicKey.getW().getAffineY()));
        raw = bos.toByteArray();
        return raw;
    }

    public static byte[] asUnsignedByteArray(
            BigInteger value) {
        byte[] bytes = value.toByteArray();

        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];

            System.arraycopy(bytes, 1, tmp, 0, tmp.length);

            return tmp;
        }

        return bytes;
    }
}

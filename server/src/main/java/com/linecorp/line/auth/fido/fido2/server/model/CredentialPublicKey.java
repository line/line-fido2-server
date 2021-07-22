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

package com.linecorp.line.auth.fido.fido2.server.model;

import java.io.IOException;
import java.io.InputStream;
import java.util.NoSuchElementException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import com.linecorp.line.auth.fido.fido2.common.server.COSEAlgorithm;
import com.linecorp.line.auth.fido.fido2.server.cose.COSEEllipticCurve;
import com.linecorp.line.auth.fido.fido2.server.cose.COSEKeyCommonParameter;
import com.linecorp.line.auth.fido.fido2.server.cose.COSEKeyType;

import lombok.Data;

@Data
public abstract class CredentialPublicKey {
    public abstract byte[] encode() throws IOException;

    public static CredentialPublicKey decode(InputStream inputStream) throws IOException {
        CredentialPublicKey credentialPublicKey;

        CBORFactory factory = new CBORFactory();
        ObjectMapper objectMapper = new ObjectMapper(factory);

        // mark current position for checking left over and handling extension
        int leftOver = inputStream.available();
        inputStream.mark(leftOver);

        JsonNode node = objectMapper.readTree(inputStream);

        if (node == null) {
            throw new IOException("CredentialPublicKey is missing");
        }

        JsonNode keyTypeNode = node.get(Integer.toString(COSEKeyCommonParameter.LABEL_KEY_TYPE));
        JsonNode algNode = node.get(Integer.toString(COSEKeyCommonParameter.LABEL_ALG));

        // check required field
        if (keyTypeNode == null) {
            throw new IOException("Key Type is missing");
        }

        if (algNode == null) {
            throw new IOException("Alg is missing");
        }

        COSEKeyType keyType;
        COSEAlgorithm algorithm;
        try {
            keyType = COSEKeyType.fromValue(keyTypeNode.asInt());
        } catch (NoSuchElementException e) {
            throw new IOException("Not supported keyType " + keyTypeNode.asInt(), e);
        }
        try {
            algorithm = COSEAlgorithm.fromValue(algNode.asInt());
        } catch (NoSuchElementException e) {
            throw new IOException("Not supported algorithm " + algNode.asInt(), e);
        }

        // rsa key type
        if (keyType == COSEKeyType.RSA) {
            JsonNode nNode = node.get("-1");
            JsonNode eNode = node.get("-2");

            // check required filed
            if (nNode == null) {
                throw new IOException("n is missing");
            }
            if (eNode == null) {
                throw new IOException("e is missing");
            }

            byte[] n = nNode.binaryValue();
            byte[] e = eNode.binaryValue();

            credentialPublicKey = RSAKey
                    .builder()
                    .algorithm(algorithm)
                    .n(n)
                    .e(e)
                    .build();

        } else if (keyType == COSEKeyType.EC2) {    // ecc key type
            JsonNode crvNode = node.get("-1");
            JsonNode xNode = node.get("-2");
            JsonNode yNode = node.get("-3");

            // check required filed
            if (crvNode == null) {
                throw new IOException("crv is missing");
            }
            if (xNode == null) {
                throw new IOException("x is missing");
            }
            if (yNode == null) {
                throw new IOException("y is missing");
            }

            COSEEllipticCurve curve;
            try {
                curve = COSEEllipticCurve.fromValue(crvNode.asInt());
            } catch (NoSuchElementException e) {
                throw new IOException("Not supported curve " + crvNode.asInt(), e);
            }
            byte[] x = xNode.binaryValue();
            byte[] y = yNode.binaryValue();

            credentialPublicKey = ECCKey.builder()
                    .algorithm(algorithm)
                    .curve(curve)
                    .x(x)
                    .y(y)
                    .build();

        } else if (keyType == COSEKeyType.OKP) {
            JsonNode crvNode = node.get("-1");
            JsonNode xNode = node.get("-2");

            // check required filed
            if (crvNode == null) {
                throw new IOException("crv is missing");
            }
            if (xNode == null) {
                throw new IOException("x is missing");
            }

            COSEEllipticCurve curve;
            try {
                curve = COSEEllipticCurve.fromValue(crvNode.asInt());
            } catch (NoSuchElementException e) {
                throw new IOException("Not supported curve " + crvNode.asInt(), e);
            }
            byte[] x = xNode.binaryValue();

            credentialPublicKey = OctetKey.builder()
                                        .algorithm(algorithm)
                                        .curve(curve)
                                        .x(x)
                                        .build();

        } else {
            throw new IOException("Not supported algorithm " + algNode.asInt());
        }

        byte[] encoded = credentialPublicKey.encode();
        // reset position at before reading public key info
        inputStream.reset();

        // skip public key info length
        inputStream.skip(encoded.length);

        return credentialPublicKey;
    }

}

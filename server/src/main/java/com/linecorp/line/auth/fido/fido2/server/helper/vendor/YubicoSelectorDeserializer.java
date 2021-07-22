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

package com.linecorp.line.auth.fido.fido2.server.helper.vendor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

import com.linecorp.line.auth.fido.fido2.server.model.metadata.yubico.FingerprintParameters;
import com.linecorp.line.auth.fido.fido2.server.model.metadata.yubico.Selector;
import com.linecorp.line.auth.fido.fido2.server.model.metadata.yubico.SelectorType;
import com.linecorp.line.auth.fido.fido2.server.model.metadata.yubico.X509ExtensionParameters;

public class YubicoSelectorDeserializer extends JsonDeserializer<Selector> {
    @Override
    public Selector deserialize(JsonParser p, DeserializationContext ctxt)
            throws IOException, JsonProcessingException {
        JsonNode node = p.getCodec().readTree(p);
        Selector selector = new Selector();
        String typeString = node.get("type").textValue();
        JsonNode parametersNode = node.get("parameters");
        SelectorType type = SelectorType.fromValue(typeString);
        selector.setType(type);
        if (type == SelectorType.FINGERPRINT) {
            JsonNode fingerprintsNode = parametersNode.get("fingerprints");
            if (fingerprintsNode.isArray()) {
                List<String> parameterList = new ArrayList<>();
                int size = fingerprintsNode.size();
                for (int i = 0; i < size; i++) {
                    parameterList.add(fingerprintsNode.get(i).textValue());
                }
                selector.setParameters(new FingerprintParameters(parameterList));
            }
        } else if (type == SelectorType.X509EXTENSION) {
            String key = parametersNode.get("key").textValue();
            String value = null;
            if (parametersNode.get("value") != null) {
                value = parametersNode.get("value").textValue();
            }
            selector.setParameters(new X509ExtensionParameters(key, value));
        }

        return selector;
    }
}

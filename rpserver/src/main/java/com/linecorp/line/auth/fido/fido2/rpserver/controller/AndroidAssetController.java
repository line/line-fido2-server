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

package com.linecorp.line.auth.fido.fido2.rpserver.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class AndroidAssetController {
    private final Environment environment;

    @Autowired
    public AndroidAssetController(Environment environment) {
        this.environment = environment;
    }

    @GetMapping(path = "/.well-known/assetlinks.json", produces = "application/json")
    public String getAssetLinks() {
        String path = "static/asset/assetlinks.json";
        if (Arrays.asList(environment.getActiveProfiles()).contains("prod")) {
            path = "static/asset/prod/assetlinks.json";
        }
        ClassPathResource resource = new ClassPathResource(path);
        String output = null;
        try {
            output = inputStreamToString(resource.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return output;
    }

    private static String inputStreamToString(InputStream in) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(in, "UTF-8"));
        StringBuilder sb = new StringBuilder();
        String line;

        while ((line = br.readLine()) != null) {
            sb.append(line).append("\n");
        }
        return sb.toString();
    }
}

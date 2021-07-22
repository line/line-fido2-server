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

import com.linecorp.line.auth.fido.fido2.common.crypto.Digests;
import com.linecorp.line.auth.fido.fido2.common.server.*;
import com.linecorp.line.auth.fido.fido2.rpserver.config.FidoServerConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.PostConstruct;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
@RestController
public class CredentialController {
    @Value("${fido2.rp.id}")
    private String rpId;
    @Value("${fido2.rp.origin}")
    private String rpOrigin;
    @Value("${fido2.rp.port}")
    private String rpPort;
    private String getDeleteCredentialsUri;
    private String fidoServerHost;
    private String scheme;

    private final RestTemplate restTemplate;
    private final FidoServerConfig fidoServerConfig;

    @Autowired
    public CredentialController(RestTemplate restTemplate, FidoServerConfig fidoServerConfig) {
        this.restTemplate = restTemplate;
        this.fidoServerConfig = fidoServerConfig;
    }

    @PostConstruct
    public void prepareUri() {
        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.newInstance();

        fidoServerHost = fidoServerConfig.getHost();
        scheme = fidoServerConfig.getScheme();

        log.info("fidoServerHost: " + fidoServerHost);
        log.info("scheme: " + scheme);

        getDeleteCredentialsUri = uriComponentsBuilder
                .scheme(scheme)
                .host(fidoServerHost)
                .port(fidoServerConfig.getPort())
                .path(fidoServerConfig.getEndpoint().getGetDeleteCredentials())
                .build().toUriString();

        uriComponentsBuilder = UriComponentsBuilder.newInstance();

    }

    @GetMapping(path = "/credentials/{id}")
    public GetCredentialResult getCredentialWithCredentialId(
            @PathVariable("id") String credentialId) {

        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(getDeleteCredentialsUri);
        URI uri = uriComponentsBuilder.path(credentialId)
                                      .queryParam("rpId", rpId)
                                      .build().toUri();

        ResponseEntity<GetCredentialResult> response = restTemplate
                .exchange(uri, HttpMethod.GET, null, GetCredentialResult.class);

        return response.getBody();
    }

    @GetMapping(path = "/credentials")
    public GetCredentialsResult getCredentialsWithUsername(
            @RequestParam("username") String username) {

        String userId = createUserId(username);
        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(getDeleteCredentialsUri);
        URI uri = uriComponentsBuilder.queryParam("rpId", rpId)
                                      .queryParam("userId", userId)
                                      .build().toUri();

        ResponseEntity<GetCredentialsResult> response = restTemplate
                .exchange(uri, HttpMethod.GET, null, GetCredentialsResult.class);

        return response.getBody();
    }

    @DeleteMapping(path = "/credentials/{id}")
    public BaseResponse deleteCredentialWithCredentialId(
            @PathVariable("id") String credentialId) {

        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(getDeleteCredentialsUri);
        URI uri = uriComponentsBuilder.path(credentialId)
                                      .queryParam("rpId", rpId)
                                      .build().toUri();

        ResponseEntity<BaseResponse> response = restTemplate
                .exchange(uri, HttpMethod.DELETE, null, BaseResponse.class);

        return response.getBody();
    }

    @DeleteMapping(path = "/credentials")
    public BaseResponse deleteCredentialWithUserName(
            @RequestParam("username") String username) {

        String userId = createUserId(username);

        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(getDeleteCredentialsUri);
        URI uri = uriComponentsBuilder.queryParam("rpId", rpId)
                                      .queryParam("userId", userId)
                                      .build().toUri();

        ResponseEntity<BaseResponse> response = restTemplate
                .exchange(uri, HttpMethod.DELETE, null, BaseResponse.class);

        return response.getBody();
    }

    private String createUserId(String username) {
        if (username == null) {
            return null;
        }

        byte[] digest = Digests.sha256(username.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}

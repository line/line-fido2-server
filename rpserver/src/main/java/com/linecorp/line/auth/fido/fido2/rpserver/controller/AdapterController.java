/*
 * Copyright 2024 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
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

import com.linecorp.line.auth.fido.fido2.common.CredentialCreationOptions;
import com.linecorp.line.auth.fido.fido2.common.CredentialRequestOptions;
import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialCreationOptions;
import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialRequestOptions;
import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialRpEntity;
import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialType;
import com.linecorp.line.auth.fido.fido2.common.crypto.Digests;
import com.linecorp.line.auth.fido.fido2.common.server.*;
import com.linecorp.line.auth.fido.fido2.rpserver.config.FidoServerConfig;
import com.linecorp.line.auth.fido.fido2.rpserver.model.AdapterAuthServerPublicKeyCredential;
import com.linecorp.line.auth.fido.fido2.rpserver.model.AdapterRegServerPublicKeyCredential;
import com.linecorp.line.auth.fido.fido2.rpserver.model.Status;
import com.linecorp.line.auth.fido.fido2.rpserver.model.transport.*;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.PostConstruct;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

@Slf4j
@RestController
public class AdapterController {
    @Value("${fido2.rp.id}")
    private String rpId;
    @Value("${fido2.rp.origin}")
    private String rpOrigin;
    @Value("${fido2.rp.port}")
    private String rpPort;
    private String regChallengeUri;
    private String regResponseUri;
    private String authChallengeUri;
    private String authResponseUri;

    private String fidoServerHost;
    private String scheme;

    private final RestTemplate restTemplate;
    private final FidoServerConfig fidoServerConfig;

    private static final String COOKIE_NAME = "fido2-session-id";

    @Autowired
    public AdapterController(RestTemplate restTemplate, FidoServerConfig fidoServerConfig) {
        this.restTemplate = restTemplate;
        this.fidoServerConfig = fidoServerConfig;
    }

    @PostConstruct
    public void prepareUri() {
        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.newInstance();

        fidoServerHost = fidoServerConfig.getHost();
        scheme = fidoServerConfig.getScheme();
        log.debug("fidoServerHost: {}", fidoServerHost);
        log.debug("scheme: {}", scheme);

        regChallengeUri = uriComponentsBuilder
                .scheme(scheme)
                .host(fidoServerHost)
                .port(fidoServerConfig.getPort())
                .path(fidoServerConfig.getEndpoint().getGetRegChallenge())
                .build().toUriString();

        uriComponentsBuilder = UriComponentsBuilder.newInstance();
        regResponseUri = uriComponentsBuilder
                .scheme(scheme)
                .host(fidoServerHost)
                .port(fidoServerConfig.getPort())
                .path(fidoServerConfig.getEndpoint().getSendRegResponse())
                .build().toUriString();

        uriComponentsBuilder = UriComponentsBuilder.newInstance();
        authChallengeUri = uriComponentsBuilder
                .scheme(scheme)
                .host(fidoServerHost)
                .port(fidoServerConfig.getPort())
                .path(fidoServerConfig.getEndpoint().getGetAuthChallenge())
                .build().toUriString();

        uriComponentsBuilder = UriComponentsBuilder.newInstance();
        authResponseUri = uriComponentsBuilder
                .scheme(scheme)
                .host(fidoServerHost)
                .port(fidoServerConfig.getPort())
                .path(fidoServerConfig.getEndpoint().getSendAuthResponse())
                .build().toUriString();

    }

    // registration
    @PostMapping("/attestation/options")
    public CredentialCreationOptionsResponse getRegistrationChallenge(
            @RequestHeader String host,
            @RequestBody CredentialCreationOptionsRequest optionsRequest,
            HttpServletResponse httpServletResponse) {

        // set header
        final HttpHeaders httpHeaders = new HttpHeaders();

        // set options
        final PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity();
        rp.setName("Test RP");
        // just for test
        rp.setId(rpId);
        final ServerPublicKeyCredentialUserEntity user = new ServerPublicKeyCredentialUserEntity();
        user.setName(optionsRequest.getUsername());
        user.setId(createUserId(optionsRequest.getUsername()));
        user.setDisplayName(optionsRequest.getDisplayName());

        final RegOptionRequest regOptionRequest = RegOptionRequest
                .builder()
                .rp(rp)
                .user(user)
                .authenticatorSelection(optionsRequest.getAuthenticatorSelection())
                .attestation(optionsRequest.getAttestation())
                .credProtect(optionsRequest.getCredProtect())
                .prf(optionsRequest.getPrf())
                .mediation(optionsRequest.getMediation())
                .build();

        final HttpEntity<RegOptionRequest> request = new HttpEntity<>(regOptionRequest, httpHeaders);
        final RegOptionResponse response = restTemplate.postForObject(regChallengeUri, request, RegOptionResponse.class);

        final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = getPublicKeyCredentialCreationOptions(response);

        final CredentialCreationOptions credentialCreationOptions = new CredentialCreationOptions();
        credentialCreationOptions.setMediation(response.getMediation());
        credentialCreationOptions.setPublicKey(publicKeyCredentialCreationOptions);

        final CredentialCreationOptionsResponse serverResponse = CredentialCreationOptionsResponse
                .builder()
                .credentialCreationOptions(credentialCreationOptions)
                .build();

        serverResponse.setStatus(Status.OK);

        httpServletResponse.addCookie(new Cookie(COOKIE_NAME, response.getSessionId()));

        return serverResponse;
    }

    private static @NonNull PublicKeyCredentialCreationOptions getPublicKeyCredentialCreationOptions(RegOptionResponse response) {
        final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions();
        publicKeyCredentialCreationOptions.setRp(response.getRp());
        publicKeyCredentialCreationOptions.setUser(response.getUser());
        publicKeyCredentialCreationOptions.setAttestation(response.getAttestation());
        publicKeyCredentialCreationOptions.setAuthenticatorSelection(response.getAuthenticatorSelection());
        publicKeyCredentialCreationOptions.setChallenge(response.getChallenge());
        publicKeyCredentialCreationOptions.setExcludeCredentials(response.getExcludeCredentials());
        publicKeyCredentialCreationOptions.setPubKeyCredParams(response.getPubKeyCredParams());
        publicKeyCredentialCreationOptions.setTimeout(response.getTimeout());
        publicKeyCredentialCreationOptions.setExtensions(response.getExtensions());

        return publicKeyCredentialCreationOptions;
    }

    @PostMapping("/attestation/result")
    public AdapterServerResponse sendRegistrationResponse(
            @RequestHeader String host,
            @RequestBody AdapterRegServerPublicKeyCredential clientResponse,
            HttpServletRequest httpServletRequest) {

        final AdapterServerResponse serverResponse;

        // get session id
        final Cookie[] cookies = httpServletRequest.getCookies();
        if (cookies == null || cookies.length == 0) {
            //error
            serverResponse = new AdapterServerResponse();
            serverResponse.setStatus(Status.FAILED);
            serverResponse.setErrorMessage("Cookie not found");
            return serverResponse;
        }

        String sessionId = null;
        for (Cookie cookie : cookies) {
            if (COOKIE_NAME.equals(cookie.getName())) {
                sessionId = cookie.getValue();
                break;
            }
        }

        // prepare origin
        final String scheme = httpServletRequest.getScheme();

        final StringBuilder builder = new StringBuilder()
                .append(scheme)
                .append("://")
                .append(rpOrigin);

        if (!StringUtils.isEmpty(rpPort)) {
            builder.append(":")
                   .append(rpPort);
        }

        // set header
        final HttpHeaders httpHeaders = new HttpHeaders();

        final RegisterCredential registerCredential = new RegisterCredential();
        final ServerRegPublicKeyCredential serverRegPublicKeyCredential = new ServerRegPublicKeyCredential();
        serverRegPublicKeyCredential.setId(clientResponse.getId());
        serverRegPublicKeyCredential.setType(clientResponse.getType());
        serverRegPublicKeyCredential.setResponse(clientResponse.getResponse());
        serverRegPublicKeyCredential.setExtensions(clientResponse.getExtensions());
        registerCredential.setServerPublicKeyCredential(serverRegPublicKeyCredential);
        registerCredential.setRpId(rpId);
        registerCredential.setSessionId(sessionId);
        registerCredential.setOrigin(builder.toString());

        final HttpEntity<RegisterCredential> request = new HttpEntity<>(registerCredential, httpHeaders);

        restTemplate.postForObject(regResponseUri, request, RegisterCredentialResult.class);

        serverResponse = new AdapterServerResponse();
        serverResponse.setStatus(Status.OK);
        return serverResponse;
    }

    // authentication
    @PostMapping("/assertion/options")
    public CredentialGetOptionsResponse getAuthenticationChallenge(
            @RequestHeader String host,
            @RequestBody CredentialGetOptionsRequest optionRequest,
            HttpServletResponse httpServletResponse) {

        // set header
        final HttpHeaders httpHeaders = new HttpHeaders();

        final AuthOptionRequest authOptionRequest = AuthOptionRequest
                .builder()
                .rpId(rpId)
                .userId(createUserId(optionRequest.getUsername()))
                .userVerification(optionRequest.getUserVerification())
                .prf(optionRequest.getPrf())
                .mediation(optionRequest.getMediation())
                .build();

        final HttpEntity<AuthOptionRequest> request = new HttpEntity<>(authOptionRequest, httpHeaders);
        final AuthOptionResponse response = restTemplate.postForObject(authChallengeUri, request, AuthOptionResponse.class);
        final boolean success = response.getServerResponse().getInternalErrorCode() == 0;

        final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions();
        publicKeyCredentialRequestOptions.setAllowCredentials(getAllowCredentials(response, optionRequest.getUsername(), success));
        publicKeyCredentialRequestOptions.setChallenge(response.getChallenge());
        publicKeyCredentialRequestOptions.setRpId(response.getRpId());
        publicKeyCredentialRequestOptions.setTimeout(response.getTimeout());
        publicKeyCredentialRequestOptions.setUserVerification(response.getUserVerification());
        publicKeyCredentialRequestOptions.setExtensions(response.getExtensions());

        final CredentialRequestOptions credentialRequestOptions = new CredentialRequestOptions();
        credentialRequestOptions.setMediation(response.getMediation());
        credentialRequestOptions.setPublicKey(publicKeyCredentialRequestOptions);

        final CredentialGetOptionsResponse serverResponse;
        serverResponse = CredentialGetOptionsResponse
                .builder()
                .credentialRequestOptions(credentialRequestOptions)
                .build();

        // error
        if (!success) {
            serverResponse.setStatus(Status.FAILED);
            serverResponse.setErrorMessage(response.getServerResponse().getInternalErrorCodeDescription());
            return serverResponse;
        }

        serverResponse.setStatus(Status.OK);

        httpServletResponse.addCookie(new Cookie(COOKIE_NAME, response.getSessionId()));

        return serverResponse;
    }

    @PostMapping("/assertion/result")
    public AdapterServerResponse sendAuthenticationResponse(
            @RequestHeader String host,
            @RequestBody AdapterAuthServerPublicKeyCredential clientResponse,
            HttpServletRequest httpServletRequest) {

        final AdapterServerResponse serverResponse;

        // get session id
        final Cookie[] cookies = httpServletRequest.getCookies();
        if (cookies == null || cookies.length == 0) {
            //error
            serverResponse = new AdapterServerResponse();
            serverResponse.setStatus(Status.FAILED);
            serverResponse.setErrorMessage("Cookie not found");
            return serverResponse;
        }

        String sessionId = null;
        for (Cookie cookie : cookies) {
            if (COOKIE_NAME.equals(cookie.getName())) {
                sessionId = cookie.getValue();
                break;
            }
        }

        // prepare origin
        final String scheme = httpServletRequest.getScheme();
        final StringBuilder builder = new StringBuilder()
                .append(scheme)
                .append("://")
                .append(rpOrigin);

        if (!StringUtils.isEmpty(rpPort)) {
            builder.append(":")
                   .append(rpPort);
        }

        // set header
        final HttpHeaders httpHeaders = new HttpHeaders();

        final VerifyCredential verifyCredential = new VerifyCredential();
        final ServerAuthPublicKeyCredential serverAuthPublicKeyCredential = new ServerAuthPublicKeyCredential();
        serverAuthPublicKeyCredential.setResponse(clientResponse.getResponse());
        serverAuthPublicKeyCredential.setId(clientResponse.getId());
        serverAuthPublicKeyCredential.setType(clientResponse.getType());
        serverAuthPublicKeyCredential.setExtensions(clientResponse.getExtensions());
        verifyCredential.setServerPublicKeyCredential(serverAuthPublicKeyCredential);
        verifyCredential.setRpId(rpId);
        verifyCredential.setSessionId(sessionId);
        verifyCredential.setOrigin(builder.toString());

        final HttpEntity<VerifyCredential> request = new HttpEntity<>(verifyCredential, httpHeaders);

        restTemplate.postForObject(authResponseUri, request, VerifyCredentialResult.class);

        serverResponse = new AdapterServerResponse();
        serverResponse.setStatus(Status.OK);
        return serverResponse;
    }

    // The FIDO2 server may return an empty allowCredentials list when the username
    // has no credentials, or when the request has no username.
    // How to handle it is an RP policy decision.
    // Returning an empty list for a username can leak whether that user exists.
    // This demo RP returns one stable fake credential as a simple mitigation.
    // A real RP should consider credential count and ID length to avoid fingerprinting.
    // Other RPs may choose a different trade-off, such as failing the request
    // or passing the empty list as-is.
    private List<ServerPublicKeyCredentialDescriptor> getAllowCredentials(
            AuthOptionResponse response,
            String username,
            boolean success) {

        final List<ServerPublicKeyCredentialDescriptor> allowCredentials = response.getAllowCredentials();
        final boolean hasUsername = StringUtils.hasLength(username);
        final boolean hasCredentials = allowCredentials != null && !allowCredentials.isEmpty();
        final boolean shouldUseImaginaryCredential = success && hasUsername && !hasCredentials;

        if (!shouldUseImaginaryCredential) {
            return allowCredentials;
        }

        // This is the username enumeration case.
        return Collections.singletonList(createImaginaryCredential(username));
    }

    private ServerPublicKeyCredentialDescriptor createImaginaryCredential(String username) {
        final ServerPublicKeyCredentialDescriptor descriptor = new ServerPublicKeyCredentialDescriptor();
        descriptor.setType(PublicKeyCredentialType.PUBLIC_KEY);
        descriptor.setId(generateImaginaryCredentialId(username));
        return descriptor;
    }

    private String generateImaginaryCredentialId(String username) {
        try {
            final String hmacAlgorithm = "HmacSHA256";

            // This demo RP uses a fixed key for simplicity.
            // A real RP should keep this key secret and load it from server-side config.
            final String key = "line-fido2-rpserver-demo-imaginary-credential-key";
            // Separates this HMAC use from other possible uses.
            final String prefix = "line-fido2-rpserver:imaginary-credential:v1";

            // Same rpId and username gives the same ID.
            // Different usernames give different-looking IDs.
            final Mac mac = Mac.getInstance(hmacAlgorithm);
            final byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
            mac.init(new SecretKeySpec(keyBytes, hmacAlgorithm));

            // Build one clear HMAC input from purpose, RP ID, and username.
            final String message = prefix + '\0' + rpId + '\0' + username;
            final byte[] credentialId = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to generate imaginary credential ID", e);
        }
    }

    private String createUserId(String username) {
        if (StringUtils.isEmpty(username)) {
            return null;
        }

        final byte[] digest = Digests.sha256(username.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}

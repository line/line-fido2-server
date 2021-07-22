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

package com.linecorp.line.auth.fido.fido2.server.service;

import com.linecorp.line.auth.fido.fido2.common.AuthenticatorTransport;
import com.linecorp.line.auth.fido.fido2.common.TokenBinding;
import com.linecorp.line.auth.fido.fido2.common.UserVerificationRequirement;
import com.linecorp.line.auth.fido.fido2.common.crypto.Digests;
import com.linecorp.line.auth.fido.fido2.common.extension.AuthenticationExtensionsClientOutputs;
import com.linecorp.line.auth.fido.fido2.common.server.*;
import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerificationResult;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.helper.CredentialPublicKeyHelper;
import com.linecorp.line.auth.fido.fido2.server.helper.ExtensionHelper;
import com.linecorp.line.auth.fido.fido2.server.helper.SignatureHelper;
import com.linecorp.line.auth.fido.fido2.server.model.*;
import com.linecorp.line.auth.fido.fido2.server.util.AaguidUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

@Slf4j
@Primary
@Service
public class ResponseServiceImpl extends ResponseCommonService implements ResponseService {

    private final SessionService sessionService;
    private final UserKeyService userKeyService;
    private final AttestationService attestationService;

    @Autowired
    public ResponseServiceImpl(
            SessionService sessionService,
            UserKeyService userKeyService,
            AttestationService attestationService) {
        this.sessionService = sessionService;
        this.userKeyService = userKeyService;
        this.attestationService = attestationService;
    }

    /**
     * Handle reg response
     * Refer following:
     * - https://www.w3.org/TR/2018/CR-webauthn-20180807/#registering-a-new-credential
     *
     * @param serverPublicKeyCredential
     * @param sessionId
     * @param origin
     * @param rpId
     * @param tokenBinding
     * @return
     */
    @Override
    public RegisterCredentialResult handleAttestation(ServerRegPublicKeyCredential serverPublicKeyCredential, String sessionId,
                                                      String origin, String rpId, TokenBinding tokenBinding) {

        // get session and check existence and served
        Session session = checkSession(sessionId);
        ServerAuthenticatorAttestationResponse attestationResponse = serverPublicKeyCredential.getResponse();

        // handle common part
        log.info("Handle common part of response");
        byte[] clientDataHsh = handleCommon("webauthn.create", session.getRegOptionResponse().getChallenge(),
                attestationResponse.getClientDataJSON(), origin, tokenBinding);

        AttestationObject attestationObject = attestationService.getAttestationObject(attestationResponse);
        attestationService.attestationObjectValidationCheck(rpId, session.getRegOptionResponse().getAuthenticatorSelection(), attestationObject);
        AttestationVerificationResult attestationVerificationResult = attestationService.verifyAttestation(clientDataHsh, attestationObject);

        // prepare trust anchors, attestation fmt (from metadata service or trusted source)
        if (!attestationVerificationResult.isSuccess()) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ATTESTATION_SIGNATURE_VERIFICATION_FAIL);
        }

        if (attestationVerificationResult.getType() != AttestationType.SELF && attestationVerificationResult.getType() != AttestationType.NONE) {
            attestationService.verifyAttestationCertificate(attestationObject, attestationVerificationResult);
        }

        return getRegisterCredentialResult(session.getRegOptionResponse(), attestationResponse.getTransports(), attestationObject.getAuthData(), attestationVerificationResult, serverPublicKeyCredential.getExtensions(), rpId);
    }

    protected RegisterCredentialResult getRegisterCredentialResult(RegOptionResponse regOptionResponse, List<AuthenticatorTransport> transports, AuthenticatorData authData, AttestationVerificationResult attestationVerificationResult, AuthenticationExtensionsClientOutputs clientExtensions, String rpId) {
        // get credential info
        log.info("Get public key credential info");
        AttestedCredentialData attestedCredentialData = authData.getAttestedCredentialData();
        String credentialId = Base64
                .getUrlEncoder()
                .withoutPadding()
                .encodeToString(attestedCredentialData.getCredentialId());
        log.info("Convert COSE public key to java public key instance");

        // check credential id is duplicated by users
        // if the duplications are exist, we may reject or deleting old registration and registering new one
        log.info("Check duplication of credential id in permanent storage");
        if (userKeyService.containsCredential(rpId, credentialId)) {
            // just reject
            throw new FIDO2ServerRuntimeException(InternalErrorCode.DUPLICATED_CREDENTIAL_ID,
                    "Duplicated credential id (" + credentialId + ")");
        }

        // store registration for latter authentication
        log.info("Store public key credential info in permanent storage");

        UserKey userKey = ExtensionHelper.createUserKeyWithExtensions(UserKey
                .builder()
                .publicKey(CredentialPublicKeyHelper.convert(attestedCredentialData.getCredentialPublicKey()))
                .aaguid(AaguidUtil.convert(attestedCredentialData.getAaguid()))
                .credentialId(credentialId)
                .id(regOptionResponse.getUser().getId())
                .name(regOptionResponse.getUser().getName())
                .displayName(regOptionResponse.getUser().getDisplayName())
                .rpId(regOptionResponse.getRp().getId())
                .algorithm(CredentialPublicKeyHelper.getCOSEAlgorithm(attestedCredentialData.getCredentialPublicKey()))
                .signCounter(authData.getSignCount())
                .attestationType(attestationVerificationResult.getType())
                .transports(transports), clientExtensions, authData.getExtensions());

        userKeyService.createUser(userKey);

        // return registration processing result
        log.info("[Finish handling attestation]");
        return createRegisterCredentialResult(authData, attestedCredentialData, credentialId, userKey);
    }

    protected RegisterCredentialResult createRegisterCredentialResult(AuthenticatorData authData, AttestedCredentialData attestedCredentialData, String credentialId, UserKey userKey) {
        return RegisterCredentialResult
                .builder()
                .aaguid(AaguidUtil.convert(attestedCredentialData.getAaguid()))
                .credentialId(credentialId)
                .attestationType(userKey.getAttestationType())
                .authenticatorTransports(userKey.getTransports())
                .userVerified(authData.isUserVerified())
                .rk(userKey.getRk())
                .credProtect(userKey.getCredProtect())
                .serverResponse(ServerResponse
                        .builder()
                        .internalErrorCode(InternalErrorCode.SUCCESS.getCode())
                        .internalError(InternalErrorCode.SUCCESS.name())
                        .build())
                .build();
    }

    @Override
    protected void checkOrigin(URI originFromClientData, URI originFromRp) {
        if (!originFromRp.toString().equals(originFromClientData.toString())) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ORIGIN_NOT_MATCHED,
                    "From collected data: " + originFromClientData + ", From request param: " + originFromRp);
        }
    }

    /**
     * Handle auth response
     * Refer following:
     * - https://www.w3.org/TR/2018/CR-webauthn-20180807/#verifying-assertion
     *
     * @param serverPublicKeyCredential
     * @param sessionId
     * @param origin
     * @param rpId
     * @param tokenBinding
     * @return
     */
    @Override
    public VerifyCredentialResult handleAssertion(ServerAuthPublicKeyCredential serverPublicKeyCredential, String sessionId,
                                                  String origin, String rpId, TokenBinding tokenBinding) {

        Session session = checkSession(sessionId);
        ServerAuthenticatorAssertionResponse assertionResponse = serverPublicKeyCredential.getResponse();
        handleCommon("webauthn.get", session.getAuthOptionResponse().getChallenge(),
                assertionResponse.getClientDataJSON(), origin, tokenBinding);

        byte[] authDataBytes = Base64.getUrlDecoder().decode(serverPublicKeyCredential.getResponse().getAuthenticatorData());
        AuthenticatorData authData = getAuthData(authDataBytes);
        checkCredentialId(serverPublicKeyCredential, session);

        UserKey userKey = getUserKey(serverPublicKeyCredential, rpId);
        verifyUserHandle(serverPublicKeyCredential, userKey);
        verifyAuthDataValues(rpId, session, authData);
        verifySignature(serverPublicKeyCredential, authDataBytes, userKey);

        checkSignCounter(authData, userKey);
        // return authentication processing result
        log.info("[Finish handling assertion]");
        return createVerifyCredentialResult(authData, userKey);
    }

    protected void checkCredentialId(ServerAuthPublicKeyCredential serverPublicKeyCredential, Session session) {
        // check credential.id is in the allow credential list (if we set the allow credential list)
        log.debug("credential ID: {}", serverPublicKeyCredential.getId());
        log.info("Check credential id in response is in the allow credential list");
        boolean credentialIdFound = false;
        if (!session.getAuthOptionResponse().getAllowCredentials().isEmpty()) {
            for (ServerPublicKeyCredentialDescriptor publicKeyCredentialDescriptor : session.getAuthOptionResponse().getAllowCredentials()) {
                if (publicKeyCredentialDescriptor.getId().equals(serverPublicKeyCredential.getId())) {
                    credentialIdFound = true;
                    break;
                }
            }
            if (!credentialIdFound) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.CREDENTIAL_ID_NOT_FOUND);
            }
        }
    }

    protected UserKey getUserKey(ServerAuthPublicKeyCredential serverPublicKeyCredential, String rpId) {
        // get user key
        log.info("Get user key with rpId and credential id");
        UserKey userKey = userKeyService.getWithCredentialId(rpId, serverPublicKeyCredential.getId());
        if (userKey == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.CREDENTIAL_COUNT_INVALID);
        }
        return userKey;
    }

    protected void verifyUserHandle(ServerAuthPublicKeyCredential serverPublicKeyCredential, UserKey userKey) {
        // check userHandle if it present
        log.info("Check userHandle if it is present, user handle MUST be identical to user id of a founded credential");
        if (!StringUtils.isEmpty(serverPublicKeyCredential.getResponse().getUserHandle())) {
            if (!userKey.getId().equals(serverPublicKeyCredential.getResponse().getUserHandle())) {
                // MUST identical to uerHandle
                throw new FIDO2ServerRuntimeException(InternalErrorCode.USER_HANDLE_NOT_MATCHED);
            }
        }
    }

    protected AuthenticatorData getAuthData(byte[] authDataBytes) {
        AuthenticatorData authData;
        try {
            authData = AuthenticatorData.decode(authDataBytes);
        } catch (IOException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.INVALID_AUTHENTICATOR_DATA);
        }
        return authData;
    }

    protected void verifyAuthDataValues(String rpId, Session session, AuthenticatorData authData) {
        // verify RP ID (compare with SHA256 hash or RP ID)
        log.info("Verify hash of RP ID with rpIdHash in authData");

        byte[] rpIdHash = Digests.sha256(rpId.getBytes(StandardCharsets.UTF_8));
        if (!Arrays.equals(authData.getRpIdHash(), rpIdHash)) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.RPID_HASH_NOT_MATCHED);
        }

        // verify user present flag
        log.info("Verify user present flag. Should be set");
        if (!authData.isUserPresent()) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.USER_PRESENCE_FLAG_NOT_SET);
        }

        // verify user verification
        log.info("Verify user verification flag if user verification required");
        if (session.getAuthOptionResponse().getUserVerification() != null &&
                session.getAuthOptionResponse().getUserVerification() == UserVerificationRequirement.REQUIRED &&
                !authData.isUserVerified()) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.USER_VERIFICATION_FLAG_NOT_SET);
        }
    }

    protected void verifySignature(ServerAuthPublicKeyCredential serverPublicKeyCredential, byte[] authDataBytes, UserKey userKey) {
        // prepare toBeSignedMessage
        log.info("Prepare toBeSignedMessage (authData + hash(cData))");
        byte[] cData = Base64.getUrlDecoder().decode(serverPublicKeyCredential.getResponse().getClientDataJSON());
        byte[] hash = Digests.sha256(cData);
        // binary concat of authData and hash
        int toBeSignedMessageSize = authDataBytes.length + hash.length;
        byte[] toBeSignedMessage = ByteBuffer
                .allocate(toBeSignedMessageSize)
                .put(authDataBytes)
                .put(hash)
                .array();

        // verify signature
        log.info("Verify signature");
        byte[] signatureBytes = Base64.getUrlDecoder().decode(serverPublicKeyCredential.getResponse().getSignature());
        boolean result = SignatureHelper.verifySignature(userKey.getPublicKey(), toBeSignedMessage, signatureBytes, userKey.getAlgorithm());
        if (!result) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.ASSERTION_SIGNATURE_VERIFICATION_FAIL);
        }
    }

    protected VerifyCredentialResult createVerifyCredentialResult(AuthenticatorData authData, UserKey userKey) {
        return VerifyCredentialResult
                .builder()
                .userId(userKey.getId())
                .userVerified(authData.isUserVerified())
                .userPresent(authData.isUserPresent())
                .serverResponse(ServerResponse
                        .builder()
                        .internalErrorCode(InternalErrorCode.SUCCESS.getCode())
                        .internalError(InternalErrorCode.SUCCESS.name())
                        .build())
                .build();
    }

    protected void checkSignCounter(AuthenticatorData authData, UserKey userKey) {
        // check signature counter
        log.info("Check signature counter");
        if (authData.getSignCount() != 0 || userKey.getSignCounter() != 0) {
            if (authData.getSignCount() > userKey.getSignCounter()) {
                // update
                userKey.setSignCounter(authData.getSignCount());
                userKeyService.update(userKey);
            } else {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.ASSERTION_SIGNATURE_VERIFICATION_FAIL);
                // authenticator is may cloned, reject.
            }
        }
    }

    protected Session checkSession(String sessionId) {
        log.info("Get session info, {}", sessionId);
        Session session = sessionService.getSession(sessionId);
        if (session == null) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.SESSION_NOT_FOUND,
                    "No such session for session id: (" + sessionId + "), Session may be expired already");
        }
        log.info("Check revoke state of session");
        if (session.isServed()) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.SESSION_ALREADY_REVOKED,
                    "Session is revoked for session id: (" + sessionId + "), Response for the session is handled already");
        }
        return session;
    }
}

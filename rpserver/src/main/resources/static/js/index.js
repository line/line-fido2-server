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

$(window).on('load', function () {
    $("#register").on('click', () => registerButtonClicked());
    $("#authenticate").on('click', () => authenticateButtonClicked());
    // $("#cancel").on('click', () => cancelButtonClicked());
    $("#check").on('click', () => checkButtonClicked());

    //Update UI to reflect availability of platform authenticator
    if (PublicKeyCredential && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
        markPlatformAuthenticatorUnavailable();
    } else if (PublicKeyCredential && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
        PublicKeyCredential
            .isUserVerifyingPlatformAuthenticatorAvailable()
            .then(available => {
                if (!available) {
                    markPlatformAuthenticatorUnavailable();
                }
            })
            .catch(e => {
                markPlatformAuthenticatorUnavailable();
            });
    }
});

const abortController = new AbortController();
const abortSignal = abortController.signal;

let performMakeCredReq = (makeCredReq) => {
    makeCredReq.challenge = base64UrlDecode(makeCredReq.challenge);
    makeCredReq.user.id = base64UrlDecode(makeCredReq.user.id);

    //Base64url decoding of id in excludeCredentials
    if (makeCredReq.excludeCredentials instanceof Array) {
        for (let i of makeCredReq.excludeCredentials) {
            if ('id' in i) {
                i.id = base64UrlDecode(i.id);
            }
        }
    }

    delete makeCredReq.status;
    delete makeCredReq.errorMessage;
    // delete makeCredReq.authenticatorSelection;

    removeEmpty(makeCredReq);

    logObject("Updating credentials ", makeCredReq)
    return makeCredReq;
}

let performGetCredReq = (getCredReq) => {
    getCredReq.challenge = base64UrlDecode(getCredReq.challenge);

    //Base64url decoding of id in allowCredentials
    if (getCredReq.allowCredentials instanceof Array) {
        for (let i of getCredReq.allowCredentials) {
          if ('id' in i) {
            i.id = base64UrlDecode(i.id);
          }
        }
    }

    delete getCredReq.status;
    delete getCredReq.errorMessage;

    removeEmpty(getCredReq);

    logObject("Updating credentials ", getCredReq)
    return getCredReq;
}

/**
 * Marks platform authenticator as unavailable in UI
 */
function markPlatformAuthenticatorUnavailable() {
    $('label[for="attachmentPlatform"]').html('On bound (platform) authenticator <span class="errorText">- Reported as not available</span>');
    // do not disable selection
    // $('#attachmentPlatform').attr('checked', false);
    // $('#attachmentPlatform').attr('disabled', true);
    // $('#attachmentCrossPlatform').attr('checked', true);
}

/**
 * Disables all input controls and buttons on the page
 */
function disableControls() {
    $('#register').attr('disabled','');
    $('#authenticate').attr('disabled','');
    $("#status").addClass('hidden');
}

/**
 * Enables all input controls and buttons on the page
 */
function enableControls() {
    $('#register').removeAttr('disabled');
    $('#authenticate').removeAttr('disabled');
    $("#status").removeClass('hidden');
}

/**
 * Handler for create button being pressed
 */
function registerButtonClicked() {
    let username  = $("input[name='username']").val();
    let displayName  = $("input[name='userDisplayName']").val();
    if (username === "") {
        $("#status").text("Input user name first");
        $("#status").removeClass('hidden');
        return;
    }
    if (displayName === "") {
      $("#status").text("Input display name first");
      $("#status").removeClass('hidden');
      return;
    }

    disableControls();
    $("#registerSpinner").removeClass("hidden");

    // authenticator selection criteria
    let specifyAuthenticatorSelection = $("input[name='specifyAuthenticatorSelection']").is(':checked');
    let specifyAuthenticatorAttachment = $("input[name='specifyAuthenticatorAttachment']").is(':checked');
    let attachment = $("input[name='attachment']:checked").val();   // optional
    let requireResidentKey = $("input[name='requireResidentKey']").is(':checked');  // default to false
    let userVerification = $("input[name='userVerificationRequired']:checked").val();
    // attestation conveyance preference
    let specifyAttestationConvenyance = $("input[name='specifyAttestationConveyance']").is(':checked');
    let attestation = $("input[name='attestationConveyancePreference']:checked").val(); // default to none
    // credProtect
    let enableCredProtect = $("input[name='enableCredProtect']").is(':checked');
    let enforceCredentialProtectionPolicy = $("input[name='enforceCredentialProtectionPolicy']").is(':checked');
    let credentialProtectionPolicy = $("input[name='credentialProtectionPolicy']:checked").val();


    // prepare parameter
    let serverPublicKeyCredentialCreationOptionsRequest = {
        username: username,
        displayName: displayName
    };

    // set authenticator selection criteria
    if (specifyAuthenticatorSelection) {
        let authenticatorSelection = {
            requireResidentKey: requireResidentKey,
            userVerification: userVerification
        };
        // set authenticator attachment
        if (specifyAuthenticatorAttachment) {
            authenticatorSelection.authenticatorAttachment = attachment;
        }
        serverPublicKeyCredentialCreationOptionsRequest.authenticatorSelection = authenticatorSelection;
    }

    // set attestation conveyance preference
    if (specifyAttestationConvenyance) {
        serverPublicKeyCredentialCreationOptionsRequest.attestation = attestation;
    }

    if (enableCredProtect) {
        serverPublicKeyCredentialCreationOptionsRequest.credProtect = {
            credentialProtectionPolicy: credentialProtectionPolicy
        };

        if (enforceCredentialProtectionPolicy) {
            serverPublicKeyCredentialCreationOptionsRequest.credProtect.enforceCredentialProtectionPolicy = enforceCredentialProtectionPolicy;
        }
    }

    getRegChallenge(serverPublicKeyCredentialCreationOptionsRequest)
        .then(createCredentialOptions => {
            return createCredential(createCredentialOptions);
        })
        .then(() => {
            $("#status").text("Successfully created credential");
            $("#registerSpinner").addClass("hidden");
            enableControls();
        })
        .catch(e => {
            $("#status").text("Error: " + e);
            $("#registerSpinner").addClass("hidden");
            enableControls();
        });
}

/**
 * Handler for get button being pressed
 */
function authenticateButtonClicked() {
    disableControls();
    $("#authenticateSpinner").removeClass("hidden");

    let username  = $("input[name='username']").val();
    let userVerification = $("input[name='userVerificationRequired']:checked").val();

    // prepare parameter
    let serverPublicKeyCredentialGetOptionsRequest = {
        username: username,
        userVerification: userVerification
    };

    getAuthChallenge(serverPublicKeyCredentialGetOptionsRequest)
        .then(getCredentialOptions => {
            return getAssertion(getCredentialOptions);
        })
        .then(() => {
            $("#status").text("Successfully verified credential");
            $("#authenticateSpinner").addClass("hidden");
            enableControls()
        }).catch(e => {
            $("#status").text("Error: " + e);
            $("#authenticateSpinner").addClass("hidden");
            $("#status").removeClass('hidden');
            enableControls()
        });
}

function cancelButtonClicked() {
    disableControls();
    $("#cancelSpinner").removeClass("hidden");
    abortController.abort();
}

function checkButtonClicked() {
    $("#status").addClass('hidden');
    let username  = $("input[name='username']").val();
    if (username === "") {
        $("#status").text("Input username first");
        $("#status").removeClass('hidden');
    } else {
    getCredentialWithUserName(username)
        .then(credentials => {
            if (credentials.length > 0) {
                $("#credentialListContainer").html(getTableWithData(credentials));
            } else {
                $("#status").text("No credential for username (" + username + ")");
                $("#status").removeClass('hidden');
            }
        }).catch(e => {
            $("#status").text("Error: " + e);
            enableControls();
        });
    }
}

function getTableWithData(credentials) {
  let table = '<div class="table-responsive">Registered Credentials\n' +
              '<table class="table table-hover">\n' +
              '  <thead>\n' +
              '    <tr>\n' +
              '      <th scope="col">#</th>\n' +
              '      <th scope="col">Data</th>\n' +
              '    </tr>\n' +
              '  </thead>\n' +
              '  <tbody>\n';
  let count = 1;
  credentials.forEach(function(credential) {
      table += '    <tr>\n' +
               '      <th scope="row">' + count + '</th>\n' +
               '      <td>' + JSON.stringify(credential, null, '\t') + '</td>\n' +
               '    </tr>';
      count++;
  });

  table += '  </tbody>\n' +
           '</table>\n' +
           '</div>';

  return table;
}


/**
 * Retrieves a reg challenge from the server
 * @returns {Promise} Promise resolving to a ArrayBuffer challenge
 */
function getRegChallenge(serverPublicKeyCredentialCreationOptionsRequest) {
    logObject("Get reg challenge", serverPublicKeyCredentialCreationOptionsRequest);
    return rest_post("/attestation/options", serverPublicKeyCredentialCreationOptionsRequest)
        .then(response => {
            logObject("Get reg challenge response", response);
            if (response.status !== 'ok') {
                return Promise.reject(response.errorMessage);
            } else {
                let createCredentialOptions = performMakeCredReq(response);
                return Promise.resolve(createCredentialOptions);
            }
        });
}

/**
 * Retrieves a auth challenge from the server
 * @returns {Promise} Promise resolving to a ArrayBuffer challenge
 */
function getAuthChallenge(serverPublicKeyCredentialGetOptionsRequest) {
    logObject("Get auth challenge", serverPublicKeyCredentialGetOptionsRequest);
    return rest_post("/assertion/options", serverPublicKeyCredentialGetOptionsRequest)
        .then(response => {
            logObject("Get auth challenge", response);
            if (response.status !== 'ok') {
                return Promise.reject(response.errorMessage);
            } else {
                let getCredentialOptions = performGetCredReq(response);
                return Promise.resolve(getCredentialOptions);
            }
        });
}

function getCredentialWithUserName(username) {
    logVariable("Get credential with username", username);
    let uri = "/credentials?username=" + username;
    return rest_get(uri)
        .then(response => {
            logObject("Get credential result", response);
            if (response.serverResponse.internalErrorCode !== 0) {
                return Promise.reject(response.serverResponse);
            } else {
                return Promise.resolve(response.credentials);
            }
        });
}

/**
 * Calls the .create() webauthn APIs and sends returns to server
 * @return {any} server response object
 */
function createCredential(options) {
    if (!PublicKeyCredential || typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
        return Promise.reject("WebAuthn APIs are not available on this user agent.");
    }

    return navigator.credentials.create({publicKey: options, signal: abortSignal})
        .then(rawAttestation => {
            logObject("raw attestation", rawAttestation);

            let attestation = {
                rawId: base64UrlEncode(rawAttestation.rawId),
                id: base64UrlEncode(rawAttestation.rawId),
                response : {
                    clientDataJSON: base64UrlEncode(rawAttestation.response.clientDataJSON),
                    attestationObject: base64UrlEncode(rawAttestation.response.attestationObject)
                },
                type: rawAttestation.type,
            };

            if (rawAttestation.getClientExtensionResults) {
                attestation.extensions = rawAttestation.getClientExtensionResults();
            }

            // set transports if it is available
            if (typeof rawAttestation.response.getTransports === "function") {
                attestation.response.transports = rawAttestation.response.getTransports();
            }

            console.log("=== Attestation response ===");
            logVariable("rawId (b64url)", attestation.rawId)
            logVariable("id (b64url)", attestation.id);
            logVariable("response.clientDataJSON (b64url)", attestation.response.clientDataJSON);
            logVariable("response.attestationObject (b64url)", attestation.response.attestationObject);
            logVariable("response.transports", attestation.response.transports);
            logVariable("id", attestation.type);

            return rest_post("/attestation/result", attestation);
        })
        .catch(function(error) {
            logVariable("create credential error", error);
            if (error == "AbortError") {
                console.info("Aborted by user");
            }
            return Promise.reject(error);
        })
        .then(response => {
            if (response.status !== 'ok') {
                return Promise.reject(response.errorMessage);
            } else {
                return Promise.resolve(response);
            }
        });
}

/**
 * Calls the .get() API and sends result to server to verify
 * @return {any} server response object
 */
function getAssertion(options) {
    if (!PublicKeyCredential) {
        return Promise.reject("WebAuthn APIs are not available on this user agent.");
    }

    return navigator.credentials.get({publicKey: options, signal: abortSignal})
        .then(rawAssertion => {
            logObject("raw assertion", rawAssertion);

            let assertion = {
                rawId: base64UrlEncode(rawAssertion.rawId),
                id: base64UrlEncode(rawAssertion.rawId),
                response: {
                  clientDataJSON: base64UrlEncode(rawAssertion.response.clientDataJSON),
                  userHandle: base64UrlEncode(rawAssertion.response.userHandle),
                  signature: base64UrlEncode(rawAssertion.response.signature),
                  authenticatorData: base64UrlEncode(rawAssertion.response.authenticatorData)
                },
                type: rawAssertion.type,
            };

            if (rawAssertion.getClientExtensionResults) {
                assertion.extensions = rawAssertion.getClientExtensionResults();
            }

            console.log("=== Assertion response ===");
            logVariable("rawId (b64url)", assertion.rawId);
            logVariable("id (b64url)", assertion.id);
            logVariable("response.userHandle (b64url)", assertion.response.userHandle);
            logVariable("response.authenticatorData (b64url)", assertion.response.authenticatorData);
            logVariable("response.lientDataJSON", assertion.response.clientDataJSON);
            logVariable("response.signature (b64url)", assertion.response.signature);
            logVariable("id", assertion.type);

            return rest_post("/assertion/result", assertion);
        })
        .catch(function(error) {
            logVariable("get assertion error", error);
            if (error == "AbortError") {
                console.info("Aborted by user");
            }
            return Promise.reject(error);
        })
        .then(response => {
            if (response.status !== 'ok') {
                return Promise.reject(response.errorMessage);
            } else {
                return Promise.resolve(response);
            }
        });
}

/**
 * Base64 url encodes an array buffer
 * @param {ArrayBuffer} arrayBuffer
 */
function base64UrlEncode(arrayBuffer) {
    if (!arrayBuffer || arrayBuffer.length == 0) {
        return undefined;
    }

    return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)))
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

/**
 * Base64 url decode
 * @param {String} base64url
 */
function base64UrlDecode(base64url) {
    let input = base64url
        .replace(/-/g, "+")
        .replace(/_/g, "/");
    let diff = input.length % 4;
    if (!diff) {
        while(diff) {
            input += '=';
            diff--;
        }
    }

    return Uint8Array.from(atob(input), c => c.charCodeAt(0));
}

function toBase64(base64url) {
    base64url = base64url.toString();
    return padString(base64url)
        .replace(/\-/g, "+")
        .replace(/_/g, "/");
}
/**
 * Converts an array buffer to a UTF-8 string
 * @param {ArrayBuffer} arrayBuffer
 * @returns {string}
 */
function arrayBufferToString(arrayBuffer) {
    return String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));
}

/**
 * Converts a string to an ArrayBuffer
 * @param {string} string string to convert
 * @returns {ArrayBuffer}
 */
function stringToArrayBuffer(str){
    return Uint8Array.from(str, c => c.charCodeAt(0)).buffer;
}

/**
 * Logs a variable to console
 * @param {string} name variable name
 * @param {string} text variable content
 */
function logVariable(name, text) {
    console.log(name + ": " + text);
}

/**
 * Logs a object to console
 * @param {string} name object name
 * @param {string} text object
 */
function logObject(name, object) {
    console.log(name + ": " + JSON.stringify(object));
}

function removeEmpty(obj) {
    for (let key in obj) {
        if (obj[key] == null || obj[key] === "") {
            delete obj[key];
        } else if (typeof obj[key] === 'object') {
            removeEmpty(obj[key]);
        }
    }
}

/**
 * Performs an HTTP get operation
 * @param {string} endpoint endpoint URL
 * @returns {Promise} Promise resolving to javascript object received back
 */
function rest_get(endpoint) {
    return fetch(endpoint, {
        method: "GET",
        credentials: "same-origin"
    })
    .then(response => {
        return response.json();
    });
}

/**
 * Performs an HTTP POST operation
 * @param {string} endpoint endpoint URL
 * @param {any} object
 * @returns {Promise} Promise resolving to javascript object received back
 */
function rest_post(endpoint, object) {
    return fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        body: JSON.stringify(object),
        headers: {
            "content-type": "application/json"
        }
    })
    .then(response => {
        return response.json();
    });
}

/**
 * Performs an HTTP put operation
 * @param {string} endpoint endpoint URL
 * @param {any} object
 * @returns {Promise} Promise resolving to javascript object received back
 */
function rest_put(endpoint, object) {
    return fetch(endpoint, {
        method: "PUT",
        credentials: "same-origin",
        body: JSON.stringify(object),
        headers: {
            "content-type": "application/json"
        }
    })
    .then(response => {
        return response.json();
    });
}
package com.linecorp.line.auth.fido.fido2.server.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.MetadataBLOBPayload;
import com.linecorp.line.auth.fido.fido2.server.config.MdsInfo;
import com.linecorp.line.auth.fido.fido2.server.exception.MdsV3MetadataException;
import com.linecorp.line.auth.fido.fido2.server.mds.MetadataTOCResult;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class MdsV3MetadataCertificateUtil {
    private static final String ALGORITHM_RS256 = "RS256";
    private static final String ALGORITHM_RS384 = "RS384";
    private static final String ALGORITHM_RS512 = "RS512";
    private static final String ALGORITHM_ES256 = "ES256";
    private static final String ALGORITHM_ES384 = "ES384";
    private static final String ALGORITHM_ES512 = "ES512";

    public static void verifyCertificate(String url, String metadataToc, MdsInfo mdsInfo, MetadataBLOBPayload metadataBLOBPayload) throws CertificateException , MdsV3MetadataException{
        List<Certificate> certificateChain = verifyCertificateChain(url, mdsInfo, JWT.decode(metadataToc),metadataBLOBPayload);
        verifySignature(metadataToc, JWT.decode(metadataToc), certificateChain.get(0), metadataBLOBPayload);
    }

    private static List<Certificate> verifyCertificateChain(String url, MdsInfo mdsInfo, DecodedJWT decodedJWT, MetadataBLOBPayload metadataBLOBPayload) throws CertificateException, MdsV3MetadataException {
        List<Certificate> certificateChain = getCertificateChain(url, mdsInfo.getRootCertificates(), decodedJWT, metadataBLOBPayload);
        Set<TrustAnchor> trustAnchors = CertificateUtil.getTrustAnchors(mdsInfo.getRootCertificates());

        try {
            boolean result = CertPathUtil.validate(certificateChain, trustAnchors, true);

            if (!result) {
                throw new MdsV3MetadataException(MetadataTOCResult
                        .builder()
                        .result(false)
                        .totalCount(metadataBLOBPayload.getEntries().size())
                        .updatedCount(0)
                        .reason("Chain validation fail")
                        .build());
            }
        } catch (GeneralSecurityException e) {
            throw new MdsV3MetadataException(MetadataTOCResult
                    .builder()
                    .result(false)
                    .totalCount(metadataBLOBPayload.getEntries().size())
                    .updatedCount(0)
                    .reason("Chain validation exception: " + e.getMessage())
                    .build());
        }

        return certificateChain;
    }

    private static List<Certificate> getCertificateChain(String url, List<String> rootCertificates, DecodedJWT decodedJWT, MetadataBLOBPayload metadataBLOBPayload) throws CertificateException, MdsV3MetadataException {
        if (!decodedJWT.getHeaderClaim("x5u").isNull()) {
            return getX5UCertificates(url, decodedJWT, metadataBLOBPayload);
        } else {
            return getX5CCertificates(rootCertificates, decodedJWT, metadataBLOBPayload);
        }
    }

    private static List<Certificate> getX5UCertificates(String url, DecodedJWT decodedJWT, MetadataBLOBPayload metadataBLOBPayload) throws CertificateException, MdsV3MetadataException {
        // refer x5u
        List<Certificate> certificateChain = new ArrayList<>();
        String x509UrlString = decodedJWT.getHeaderClaim("x5u").asString();

        URL x509Url, tocUrl;
        try {
            x509Url = new URL(x509UrlString);
            tocUrl = new URL(url);

        } catch (MalformedURLException e) {
            throw new MdsV3MetadataException(MetadataTOCResult
                    .builder()
                    .result(false)
                    .totalCount(metadataBLOBPayload.getEntries().size())
                    .updatedCount(0)
                    .reason("URL for x5u is not valid")
                    .build());
        }

        if (!x509Url.getHost().equals(tocUrl.getHost())) {
            throw new MdsV3MetadataException(MetadataTOCResult
                    .builder()
                    .result(false)
                    .totalCount(metadataBLOBPayload.getEntries().size())
                    .updatedCount(0)
                    .reason("x5u origin differs to Metadata TOC origin")
                    .build());
        }

        // retrieve x509 certificate or certificate chain (PEM)
        String pemEncoded = ""; // need to get from x5u url
        String[] certificateParts = pemEncoded.split("-----END CERTIFICATE-----");
        for (String certificate : certificateParts) {
            certificateChain.add(
                    CertificateUtil.getCertificate(certificate.replaceAll("\"-----BEGIN CERTIFICATE-----\"", "").replaceAll("\n", "")));
        }
        return certificateChain;
    }

    private static List<Certificate> getX5CCertificates(List<String> rootCertificates, DecodedJWT decodedJWT, MetadataBLOBPayload metadataBLOBPayload) throws CertificateException, MdsV3MetadataException {
        List<Certificate> certificateChain;
        // get chain with x5c
        Claim x5c = decodedJWT.getHeaderClaim("x5c");

        if (!x5c.isNull()) {
            // refer x5c
            List<String> derEncodedCertificates = x5c.asList(String.class);

            if (derEncodedCertificates == null ||
                    derEncodedCertificates.isEmpty()) {
                // error
                throw new MdsV3MetadataException(MetadataTOCResult
                        .builder()
                        .result(false)
                        .totalCount(metadataBLOBPayload.getEntries().size())
                        .updatedCount(0)
                        .reason("x5c is empty")
                        .build());
            } else {
                certificateChain = CertificateUtil.getCertificatesFromStringList(derEncodedCertificates);
            }

        } else {
            // consider trust anchor as signing chain
            certificateChain = CertificateUtil.getCertificatesFromStringList(rootCertificates);
        }
        return certificateChain;
    }

    private static void verifySignature(String metadataToc, DecodedJWT decodedJWT, Certificate signingCertificate, MetadataBLOBPayload metadataBLOBPayload) throws MdsV3MetadataException {
        PublicKey publicKey = signingCertificate.getPublicKey();

        // get jwt signature algorithm and hash algorithm
        Algorithm signatureAlgorithm = getSignatureAlgorithm(decodedJWT, metadataBLOBPayload, publicKey);
        JWTVerifier jwtVerifier = JWT.require(signatureAlgorithm).build();
        try {
            jwtVerifier.verify(metadataToc);
        } catch (AlgorithmMismatchException | SignatureVerificationException | TokenExpiredException |
                 InvalidClaimException e) {
            throw new MdsV3MetadataException(MetadataTOCResult
                    .builder()
                    .result(false)
                    .totalCount(metadataBLOBPayload.getEntries().size())
                    .updatedCount(0)
                    .reason("Signature verification fail: " + e.getMessage())
                    .build());
        }
    }

    private static Algorithm getSignatureAlgorithm(DecodedJWT decodedJWT, MetadataBLOBPayload metadataBLOBPayload, PublicKey publicKey) throws MdsV3MetadataException {
        String algorithm = decodedJWT.getAlgorithm();
        Algorithm signatureAlgorithm;

        if (ALGORITHM_RS256.equals(algorithm)) {
            signatureAlgorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);

        } else if (ALGORITHM_RS384.equals(algorithm)) {
            signatureAlgorithm = Algorithm.RSA384((RSAPublicKey) publicKey, null);

        } else if (ALGORITHM_RS512.equals(algorithm)) {
            signatureAlgorithm = Algorithm.RSA512((RSAPublicKey) publicKey, null);

        } else if (ALGORITHM_ES256.equals(algorithm)) {
            signatureAlgorithm = Algorithm.ECDSA256((ECPublicKey) publicKey, null);

        } else if (ALGORITHM_ES384.equals(algorithm)) {
            signatureAlgorithm = Algorithm.ECDSA384((ECPublicKey) publicKey, null);

        } else if (ALGORITHM_ES512.equals(algorithm)) {
            signatureAlgorithm = Algorithm.ECDSA512((ECPublicKey) publicKey, null);

        } else {
            throw new MdsV3MetadataException(MetadataTOCResult
                    .builder()
                    .result(false)
                    .totalCount(metadataBLOBPayload.getEntries().size())
                    .updatedCount(0)
                    .reason("Not supported signature algorithm: " + algorithm)
                    .build());
        }
        return signatureAlgorithm;
    }
}

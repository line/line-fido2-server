package com.linecorp.line.auth.fido.fido2.common.mdsv3;

import com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata.BiometricStatusReport;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata.MetadataStatement;
import lombok.Data;

import java.util.List;

@Data
public class MetadataBLOBPayloadEntry {
    private String aaid;
    private String aaguid;
    private List<String> attestationCertificateKeyIdentifiers;
    private MetadataStatement metadataStatement;
    private List<BiometricStatusReport> biometricStatusReports;

    private List<StatusReport> statusReports;
    private String timeOfLastStatusChange;
    private String rogueListURL;
    private StringBuilder rogueListHash;
}

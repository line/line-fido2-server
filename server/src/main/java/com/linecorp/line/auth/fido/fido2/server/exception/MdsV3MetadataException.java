package com.linecorp.line.auth.fido.fido2.server.exception;

import com.linecorp.line.auth.fido.fido2.server.mds.MetadataTOCResult;
import lombok.Getter;

@Getter
public class MdsV3MetadataException extends RuntimeException{
    public MetadataTOCResult metadataTOCResult;

    public MdsV3MetadataException(MetadataTOCResult metadataTOCResult) {
        this.metadataTOCResult = metadataTOCResult;
    }
}

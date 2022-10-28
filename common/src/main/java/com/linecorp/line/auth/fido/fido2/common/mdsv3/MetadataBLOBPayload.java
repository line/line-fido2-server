package com.linecorp.line.auth.fido.fido2.common.mdsv3;

import lombok.Data;

import java.util.List;
@Data
public class MetadataBLOBPayload {
    private String legalHeader;
    private long no;
    private String nextUpdate;
    private List<MetadataBLOBPayloadEntry> entries;
}

package com.forticode.cipherise;

public class ServerInformation {
    public final String serverVersion;
    public final String buildVersion;
    public final String appMinVersion;
    public final int maxPayloadSize;

    ServerInformation(String serverVersion, String buildVersion, String appMinVersion, int maxPayloadSize) {
        this.serverVersion = serverVersion;
        this.buildVersion = buildVersion;
        this.appMinVersion = appMinVersion;
        this.maxPayloadSize = maxPayloadSize;
    }
}
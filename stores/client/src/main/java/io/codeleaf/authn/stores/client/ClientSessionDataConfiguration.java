package io.codeleaf.authn.stores.client;

import io.codeleaf.config.Configuration;

public final class ClientSessionDataConfiguration implements Configuration {

    private final boolean encrypted;
    private final long timeoutTime;
    private final String secret;

    ClientSessionDataConfiguration(boolean encrypted, long timeoutTime, String secret) {
        this.encrypted = encrypted;
        this.timeoutTime = timeoutTime;
        this.secret = secret;
    }

    public boolean isEncrypted() {
        return encrypted;
    }

    public long getTimeoutTime() {
        return timeoutTime;
    }

    public String getSecret() {
        return secret;
    }
}

package io.codeleaf.authn.jaxrs.protocols.header;

import io.codeleaf.config.Configuration;

public final class HeaderSessionIdConfiguration implements Configuration {

    private final String headerName;

    public HeaderSessionIdConfiguration(String headerName) {
        this.headerName = headerName;
    }

    public String getHeaderName() {
        return headerName;
    }
}

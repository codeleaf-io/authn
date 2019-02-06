package io.codeleaf.authn.jaxrs.basic;

import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;
import io.codeleaf.config.Configuration;

public final class BasicConfiguration implements Configuration {

    private final PasswordRequestAuthenticator authenticator;

    BasicConfiguration(PasswordRequestAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    public PasswordRequestAuthenticator getAuthenticator() {
        return authenticator;
    }
}

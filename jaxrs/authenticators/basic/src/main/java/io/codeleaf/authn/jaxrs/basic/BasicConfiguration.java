package io.codeleaf.authn.jaxrs.basic;

import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;
import io.codeleaf.config.Configuration;

public final class BasicConfiguration implements Configuration {

    private final PasswordRequestAuthenticator authenticator;
    private final String realm;
    private final boolean prompt;

    BasicConfiguration(PasswordRequestAuthenticator authenticator, String realm, boolean prompt) {
        this.authenticator = authenticator;
        this.realm = realm;
        this.prompt = prompt;
    }

    public PasswordRequestAuthenticator getAuthenticator() {
        return authenticator;
    }

    public String getRealm() {
        return realm;
    }

    public boolean prompt() {
        return prompt;
    }
}

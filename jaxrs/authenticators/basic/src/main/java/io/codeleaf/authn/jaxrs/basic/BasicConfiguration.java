package io.codeleaf.authn.jaxrs.basic;

import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;
import io.codeleaf.config.Configuration;

import java.net.URI;

public final class BasicConfiguration implements Configuration {

    private final PasswordRequestAuthenticator authenticator;
    private final String loginMethod;
    private final String formUri;

    BasicConfiguration(PasswordRequestAuthenticator authenticator, String loginMethod, String formUri) {
        this.authenticator = authenticator;
        this.loginMethod = loginMethod;
        this.formUri = formUri;
    }

    public PasswordRequestAuthenticator getAuthenticator() {
        return authenticator;
    }

    public boolean isFormLogin() {
        return loginMethod.equals("form");
    }

    public URI getFormUri() {
        if (loginMethod.equals("form"))
            return URI.create(formUri);
        return null;
    }
}

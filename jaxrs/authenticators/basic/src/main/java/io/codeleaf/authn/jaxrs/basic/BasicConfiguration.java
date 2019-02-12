package io.codeleaf.authn.jaxrs.basic;

import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;
import io.codeleaf.config.Configuration;

import java.net.URI;

public final class BasicConfiguration implements Configuration {

    private final PasswordRequestAuthenticator authenticator;
    private final String realm;
    private final boolean isForm;
    private final URI formUri;

    BasicConfiguration(PasswordRequestAuthenticator authenticator, String realm, boolean isForm, URI formUri) {
        this.authenticator = authenticator;
        this.realm = realm;
        this.isForm = isForm;
        this.formUri = formUri;
    }

    public PasswordRequestAuthenticator getAuthenticator() {
        return authenticator;
    }

    public String getRealm() {
        return realm;
    }

    public boolean isForm() {
        return isForm;
    }

    public URI getFormUri() {
        return formUri;
    }
}

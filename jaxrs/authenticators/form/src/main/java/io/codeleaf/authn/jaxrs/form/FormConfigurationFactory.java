package io.codeleaf.authn.jaxrs.form;

import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;
import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.SettingNotFoundException;
import io.codeleaf.config.spec.Specification;
import io.codeleaf.config.util.Specifications;

import java.net.URI;

public final class FormConfigurationFactory extends AbstractConfigurationFactory<FormConfiguration> {

    public FormConfigurationFactory() {
        super(FormConfiguration.class);
    }

    @Override
    public FormConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        try {
            return new FormConfiguration(
                    getAuthenticator(specification),
                    getCustomLoginFormUri(specification),
                    getUsernameField(specification),
                    getPasswordField(specification));
        } catch (IllegalArgumentException cause) {
            throw new InvalidSpecificationException(specification, "Can't parse specification: " + cause.getMessage(), cause);
        }
    }

    private PasswordRequestAuthenticator getAuthenticator(Specification specification) throws InvalidSpecificationException {
        String authenticatorName = Specifications.parseString(specification, "passwordAuthenticator");
        PasswordRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(authenticatorName, PasswordRequestAuthenticator.class);
        if (authenticator == null) {
            throw new InvalidSpecificationException(specification, "No authenticator found with name: " + authenticatorName);
        }
        return authenticator;
    }

    private URI getCustomLoginFormUri(Specification specification) throws SettingNotFoundException {
        return specification.hasSetting("loginUri")
                ? URI.create(Specifications.parseString(specification, "loginUri"))
                : null;
    }

    private String getUsernameField(Specification specification) throws SettingNotFoundException {
        return specification.hasSetting("usernameField")
                ? Specifications.parseString(specification, "usernameField")
                : "username";
    }

    private String getPasswordField(Specification specification) throws SettingNotFoundException {
        return specification.hasSetting("passwordField")
                ? Specifications.parseString(specification, "passwordField")
                : "password";
    }
}

package io.codeleaf.authn.jaxrs.basic;

import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;
import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSettingException;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.SettingNotFoundException;
import io.codeleaf.config.spec.Specification;
import io.codeleaf.config.util.Specifications;

public final class BasicConfigurationFactory extends AbstractConfigurationFactory<BasicConfiguration> {

    public BasicConfigurationFactory() {
        super(BasicConfiguration.class);
    }

    @Override
    public BasicConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        try {
            return new BasicConfiguration(
                    getAuthenticator(specification),
                    getRealm(specification),
                    getPrompt(specification));
        } catch (IllegalArgumentException cause) {
            throw new InvalidSpecificationException(specification, "Can't parse specification: " + cause.getMessage(), cause);
        }
    }

    private String getRealm(Specification specification) throws SettingNotFoundException {
        return specification.hasSetting("realm")
                ? Specifications.parseString(specification, "realm")
                : "Secured Application";
    }

    private PasswordRequestAuthenticator getAuthenticator(Specification specification) throws InvalidSpecificationException {
        String authenticatorName = Specifications.parseString(specification, "passwordAuthenticator");
        PasswordRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(authenticatorName, PasswordRequestAuthenticator.class);
        if (authenticator == null) {
            throw new InvalidSpecificationException(specification, "No authenticator found with name: " + authenticatorName);
        }
        return authenticator;
    }

    private boolean getPrompt(Specification specification) throws SettingNotFoundException, InvalidSettingException {
        return !specification.hasSetting("prompt") || Specifications.parseBoolean(specification, "prompt");
    }
}

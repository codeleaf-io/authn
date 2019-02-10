package io.codeleaf.authn.jaxrs.basic;

import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;
import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.Specification;

public final class BasicConfigurationFactory extends AbstractConfigurationFactory<BasicConfiguration> {

    public BasicConfigurationFactory() {
        super(BasicConfiguration.class);
    }

    @Override
    protected BasicConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        try {
            String authenticatorName = specification.getValue(String.class, "passwordAuthenticator");
            PasswordRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(authenticatorName, PasswordRequestAuthenticator.class);
            if (authenticator == null) {
                throw new InvalidSpecificationException(specification, "No authenticator found with name: " + authenticatorName);
            }
            return new BasicConfiguration(authenticator, specification.getValue(String.class, "loginMethod"), specification.getValue(String.class, "formUri"));
        } catch (IllegalArgumentException cause) {
            throw new InvalidSpecificationException(specification, "Can't parse specification: " + cause.getMessage(), cause);
        }
    }
}

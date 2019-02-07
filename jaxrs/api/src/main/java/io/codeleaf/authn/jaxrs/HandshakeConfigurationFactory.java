package io.codeleaf.authn.jaxrs;

import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.Specification;

public final class HandshakeConfigurationFactory extends AbstractConfigurationFactory<HandshakeConfiguration> {

    private static final HandshakeConfiguration DEFAULT = new HandshakeConfiguration("/auth", null, null);

    public HandshakeConfigurationFactory() {
        super(DEFAULT);
    }

    @Override
    protected HandshakeConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        return null;
    }
}

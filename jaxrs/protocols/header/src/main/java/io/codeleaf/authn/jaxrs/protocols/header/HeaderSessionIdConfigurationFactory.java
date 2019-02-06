package io.codeleaf.authn.jaxrs.protocols.header;

import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.Specification;

public final class HeaderSessionIdConfigurationFactory extends AbstractConfigurationFactory<HeaderSessionIdConfiguration> {

    private final HeaderSessionIdConfiguration DEFAULT = new HeaderSessionIdConfiguration("X-Authentication");

    public HeaderSessionIdConfigurationFactory(HeaderSessionIdConfiguration defaultConfiguration) {
        super(defaultConfiguration);
    }

    @Override
    protected HeaderSessionIdConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        if (specification.hasSetting("headerName")) {
            return new HeaderSessionIdConfiguration(specification.getValue(String.class, "headerName"));
        }
        return DEFAULT;
    }
}

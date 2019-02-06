package io.codeleaf.authn.jaxrs.protocols.cookie;

import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.Specification;
import io.codeleaf.config.util.Specifications;

public final class CookieSessionIdConfigurationFactory extends AbstractConfigurationFactory<CookieSessionIdConfiguration> {

    private static final CookieSessionIdConfiguration DEFAULT = new CookieSessionIdConfiguration("Authentication", null, null, null, 60_000, true, true);

    public CookieSessionIdConfigurationFactory() {
        super(DEFAULT);
    }

    @Override
    protected CookieSessionIdConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        return new CookieSessionIdConfiguration(
                specification.hasSetting("name") ? specification.getValue(String.class, "name") : DEFAULT.getName(),
                specification.hasSetting("path") ? specification.getValue(String.class, "path") : DEFAULT.getPath(),
                specification.hasSetting("domain") ? specification.getValue(String.class, "domain") : DEFAULT.getDomain(),
                specification.hasSetting("comment") ? specification.getValue(String.class, "comment") : DEFAULT.getComment(),
                specification.hasSetting("maxAge") ? Specifications.parseInt(specification, "maxAge") : DEFAULT.getMaxAge(),
                specification.hasSetting("secure") ? Specifications.parseBoolean(specification, "secure") : DEFAULT.isSecure(),
                specification.hasSetting("httpOnly") ? Specifications.parseBoolean(specification, "httpOnly") : DEFAULT.isHttpOnly());
    }
}

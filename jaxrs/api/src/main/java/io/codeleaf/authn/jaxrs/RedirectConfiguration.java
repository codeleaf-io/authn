package io.codeleaf.authn.jaxrs;

import io.codeleaf.config.Configuration;
import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.Specification;
import io.codeleaf.config.util.Specifications;

import java.net.URI;

public final class RedirectConfiguration implements Configuration {

    private final URI redirectUri;

    public RedirectConfiguration(URI redirectUri) {
        this.redirectUri = redirectUri;
    }

    public URI getRedirectURI() {
        return redirectUri;
    }

    public static final class Factory extends AbstractConfigurationFactory<RedirectConfiguration> {

        public Factory() {
            super(RedirectConfiguration.class);
        }

        @Override
        protected RedirectConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
            return new RedirectConfiguration(URI.create(Specifications.parseString(specification, "redirectUrl")));
        }
    }
}

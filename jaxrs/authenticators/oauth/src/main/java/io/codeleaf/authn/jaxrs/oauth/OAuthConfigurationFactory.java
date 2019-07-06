package io.codeleaf.authn.jaxrs.oauth;

import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.Specification;
import io.codeleaf.config.util.Specifications;

import java.net.URI;
import java.net.URISyntaxException;

public final class OAuthConfigurationFactory extends AbstractConfigurationFactory<OAuthConfiguration> {

    public OAuthConfigurationFactory() {
        super(OAuthConfiguration.class);
    }

    @Override
    public OAuthConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        try {
            return new OAuthConfiguration(
                    Specifications.parseString(specification, "clientId"),
                    Specifications.parseString(specification, "clientSecret"),
                    new URI(Specifications.parseString(specification, "redirectUri")),
                    Specifications.parseString(specification, "scope"),
                    Specifications.parseString(specification, "state"),
                    Specifications.parseString(specification, "landingPageUrl"));
        } catch (URISyntaxException cause) {
            throw new InvalidSpecificationException(specification, "Invalid redirect URI.", cause);
        }
    }
}


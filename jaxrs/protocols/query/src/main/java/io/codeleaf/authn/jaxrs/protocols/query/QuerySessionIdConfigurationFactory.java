package io.codeleaf.authn.jaxrs.protocols.query;

import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.Specification;
import io.codeleaf.config.util.Specifications;

public final class QuerySessionIdConfigurationFactory extends AbstractConfigurationFactory<QuerySessionIdConfiguration> {

    private static final QuerySessionIdConfiguration DEFAULT = new QuerySessionIdConfiguration("");

    public QuerySessionIdConfigurationFactory() {
        super(DEFAULT);
    }

    @Override
    protected QuerySessionIdConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        return new QuerySessionIdConfiguration(
                specification.hasSetting("parameterName") ? Specifications.parseString(specification, "parameterName") : DEFAULT.getParameterName());
    }
}
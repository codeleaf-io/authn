package io.codeleaf.authn.password.dummy;

import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.Specification;
import io.codeleaf.config.util.Specifications;

public final class DummyConfigurationFactory extends AbstractConfigurationFactory<DummyConfiguration> {

    public DummyConfigurationFactory() {
        super(DummyConfiguration.getDefault());
    }

    @Override
    public DummyConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        return new DummyConfiguration(
                Specifications.parseString(specification, "userName"),
                Specifications.parseString(specification, "password"));
    }
}

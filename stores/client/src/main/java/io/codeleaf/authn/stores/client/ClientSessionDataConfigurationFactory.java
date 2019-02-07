package io.codeleaf.authn.stores.client;

import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSettingException;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.SettingNotFoundException;
import io.codeleaf.config.spec.Specification;
import io.codeleaf.config.util.Specifications;

import java.util.UUID;

public final class ClientSessionDataConfigurationFactory extends AbstractConfigurationFactory<ClientSessionDataConfiguration> {

    private static final ClientSessionDataConfiguration DEFAULT = new ClientSessionDataConfiguration(true, 60_000, UUID.randomUUID().toString());

    public ClientSessionDataConfigurationFactory() {
        super(DEFAULT);
    }

    @Override
    protected ClientSessionDataConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        return new ClientSessionDataConfiguration(
                specification.hasSetting("encrypted") ? Specifications.parseBoolean(specification, "encrypted") : DEFAULT.isEncrypted(),
                parseTimeout(specification),
                specification.hasSetting("secret") ? Specifications.parseString(specification, "secret") : DEFAULT.getSecret());
    }

    private long parseTimeout(Specification specification) throws SettingNotFoundException, InvalidSettingException {
        if (!specification.hasSetting("timeoutTime")) {
            return DEFAULT.getTimeoutTime();
        }
        try {
            String timeoutTime = Specifications.parseString(specification, "timeoutTime");
            long value;
            if (timeoutTime.endsWith("ms")) {
                value = Long.parseLong(timeoutTime.substring(0, timeoutTime.length() - 2));
            } else if (timeoutTime.endsWith("s")) {
                value = Long.parseLong(timeoutTime.substring(0, timeoutTime.length() - 1)) * 1_000;
            } else if (timeoutTime.endsWith("m")) {
                value = Long.parseLong(timeoutTime.substring(0, timeoutTime.length() - 1)) * 60 * 1_000;
            } else {
                value = Long.parseLong(timeoutTime);
            }
            return value;
        } catch (IllegalArgumentException cause) {
            throw new InvalidSettingException(specification, specification.getSetting("timeoutTime"), cause);
        }
    }
}

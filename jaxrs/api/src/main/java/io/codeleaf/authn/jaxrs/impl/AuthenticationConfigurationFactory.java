package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.jaxrs.AuthenticationPolicy;
import io.codeleaf.authn.jaxrs.AuthenticationConfiguration;
import io.codeleaf.config.Configuration;
import io.codeleaf.config.ConfigurationNotFoundException;
import io.codeleaf.config.ConfigurationProvider;
import io.codeleaf.config.impl.AbstractConfigurationFactory;
import io.codeleaf.config.spec.InvalidSettingException;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.SettingNotFoundException;
import io.codeleaf.config.spec.Specification;
import io.codeleaf.config.spec.impl.MapSpecification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

public final class AuthenticationConfigurationFactory extends AbstractConfigurationFactory<AuthenticationConfiguration> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationConfigurationFactory.class);

    public AuthenticationConfigurationFactory() {
        super(AuthenticationConfiguration.getDefault());
    }

    @Override
    protected AuthenticationConfiguration parseConfiguration(Specification specification) throws InvalidSpecificationException {
        Map<String, AuthenticationConfiguration.Authenticator> authenticators = new LinkedHashMap<>();
        for (String authenticatorName : specification.getChilds("authenticators")) {
            authenticators.put(authenticatorName, parseAuthenticator(authenticatorName, specification));
        }
        List<AuthenticationConfiguration.Zone> zones = new ArrayList<>();
        for (String zoneName : specification.getChilds("zones")) {
            zones.add(parseZone(zoneName, specification, authenticators));
        }
        return AuthenticationConfiguration.create(zones, authenticators);
    }

    private AuthenticationConfiguration.Zone parseZone(String zoneName, Specification specification, Map<String, AuthenticationConfiguration.Authenticator> authenticators) throws SettingNotFoundException, InvalidSettingException {
        return new AuthenticationConfiguration.Zone(
                zoneName,
                parsePolicy(specification, specification.getSetting("zones", zoneName, "policy")),
                parseEndpoints(specification, specification.getSetting("zones", zoneName, "endpoints")),
                parseAuthenticator(specification, specification.getSetting("zones", zoneName, "authenticator"), authenticators));
    }

    private AuthenticationPolicy parsePolicy(Specification specification, Specification.Setting setting) throws InvalidSettingException {
        if (!(setting.getValue() instanceof String)) {
            throw new InvalidSettingException(specification, setting, "policy must be a String!");
        }
        AuthenticationPolicy policy;
        switch ((String) setting.getValue()) {
            case "none":
                policy = AuthenticationPolicy.NONE;
                break;
            case "optional":
                policy = AuthenticationPolicy.OPTIONAL;
                break;
            case "required":
                policy = AuthenticationPolicy.REQUIRED;
                break;
            default:
                throw new InvalidSettingException(specification, setting, "Invalid policy value, must be: none, optional or required!");
        }
        return policy;
    }

    private List<String> parseEndpoints(Specification specification, Specification.Setting setting) throws InvalidSettingException {
        List<String> endpoints;
        if (setting.getValue() instanceof String) {
            endpoints = Collections.singletonList((String) setting.getValue());
        } else if (setting.getValue() instanceof List) {
            endpoints = new ArrayList<>();
            for (Object item : ((List<?>) setting.getValue())) {
                if (!(item instanceof String)) {
                    throw new InvalidSettingException(specification, setting, "Endpoints must only contain Strings!");
                } else {
                    endpoints.add((String) item);
                }
            }
        } else {
            throw new InvalidSettingException(specification, setting, "Endpoints must be a String or list of Strings!");
        }
        return endpoints;
    }

    private AuthenticationConfiguration.Authenticator parseAuthenticator(Specification specification, Specification.Setting setting, Map<String, AuthenticationConfiguration.Authenticator> authenticators) throws InvalidSettingException {
        if (!(setting.getValue() instanceof String)) {
            throw new InvalidSettingException(specification, setting, "Must be a String!");
        }
        String authenticatorName = (String) setting.getValue();
        if (!authenticators.containsKey(authenticatorName)) {
            throw new InvalidSettingException(specification, setting, "No authenticator defined with name: " + authenticatorName);
        }
        return authenticators.get(authenticatorName);
    }

    private AuthenticationConfiguration.Authenticator parseAuthenticator(String authenticatorName, Specification specification) throws InvalidSpecificationException {
        AuthenticationConfiguration.Authenticator authenticator = new AuthenticationConfiguration.Authenticator(
                authenticatorName,
                parseClass(specification, specification.getSetting("authenticators", authenticatorName, "implementation")),
                parseAuthenticationConfiguration(authenticatorName, specification));
        initializeAuthenticator(specification, authenticator);
        return authenticator;
    }

    private Class<?> parseClass(Specification specification, Specification.Setting setting) throws InvalidSettingException {
        if (!(setting.getValue() instanceof String)) {
            throw new InvalidSettingException(specification, setting, "Implementation must be a String!");
        }
        try {
            return Class.forName((String) setting.getValue());
        } catch (ClassNotFoundException cause) {
            throw new InvalidSettingException(specification, setting, "Could not find class: " + setting.getValue(), cause);
        }
    }

    @SuppressWarnings("unchecked")
    private Configuration parseAuthenticationConfiguration(String authenticatorName, Specification specification) throws InvalidSpecificationException {
        Specification.Setting configTypeSetting = specification.getSetting("authenticators", authenticatorName, "configuration", "type");
        Class<?> configurationClass = parseClass(specification, configTypeSetting);
        if (!Configuration.class.isAssignableFrom(configurationClass)) {
            throw new InvalidSettingException(specification, configTypeSetting, "Configuration type is not implementing Configuration: " + configTypeSetting.getValue());
        }
        try {
            Specification configSpecification = MapSpecification.create(specification, "authenticators", authenticatorName, "configuration", "settings");
            return ConfigurationProvider.get().parseConfiguration((Class<? extends Configuration>) configurationClass, configSpecification);
        } catch (ConfigurationNotFoundException cause) {
            throw new InvalidSettingException(specification, specification.getSetting("authenticators", authenticatorName, "configuration", "settings"), cause.getCause());
        }
    }

    private void initializeAuthenticator(Specification specification, AuthenticationConfiguration.Authenticator authenticator) throws InvalidSpecificationException {
        try {
            LOGGER.debug("Initializing authenticator: " + authenticator.getName());
            Class<? extends Configuration> configClass = authenticator.getConfiguration().getClass();
            Method method = authenticator.getImplementationClass().getMethod("create", configClass);
            Object instance = method.invoke(null, authenticator.getConfiguration());
            AuthenticatorRegistry.register(authenticator.getName(), instance);
        } catch (NoSuchMethodException | IllegalAccessException | IllegalStateException | InvocationTargetException cause) {
            LOGGER.error("Failed to initialize authenticator: " + cause.getMessage());
            throw new InvalidSpecificationException(specification, cause.getMessage(), cause);
        }
    }
}

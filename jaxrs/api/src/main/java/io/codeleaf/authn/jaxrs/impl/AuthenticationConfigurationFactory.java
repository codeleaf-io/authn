package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.impl.AuthenticatorRegistries;
import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.impl.DefaultAuthenticatorRegistry;
import io.codeleaf.authn.jaxrs.AuthenticationConfiguration;
import io.codeleaf.authn.jaxrs.AuthenticationPolicy;
import io.codeleaf.authn.jaxrs.HandshakeConfiguration;
import io.codeleaf.common.utils.Types;
import io.codeleaf.config.Configuration;
import io.codeleaf.config.ConfigurationException;
import io.codeleaf.config.ConfigurationNotFoundException;
import io.codeleaf.config.ConfigurationProvider;
import io.codeleaf.config.impl.ContextAwareConfigurationFactory;
import io.codeleaf.config.spec.InvalidSettingException;
import io.codeleaf.config.spec.InvalidSpecificationException;
import io.codeleaf.config.spec.SettingNotFoundException;
import io.codeleaf.config.spec.Specification;
import io.codeleaf.config.spec.impl.MapSpecification;
import io.codeleaf.config.util.Specifications;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.*;
import java.util.*;

public final class AuthenticationConfigurationFactory extends ContextAwareConfigurationFactory<AuthenticationConfiguration, AuthenticatorRegistry> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationConfigurationFactory.class);

    //TODO: Fix by passing correct specification - Aug 7: What is meant with this TODO?
    private static final AuthenticationConfiguration DEFAULT;

    static {
        try {
            DEFAULT = AuthenticationConfiguration.create(
                    Collections.emptyList(),
                    Collections.emptyMap(),
                    AuthenticatorRegistries.emptyRegistry(),
                    ConfigurationProvider.get().getConfiguration(HandshakeConfiguration.class));
        } catch (ConfigurationException | IOException cause) {
            throw new ExceptionInInitializerError(cause);
        }
    }

    public AuthenticationConfigurationFactory() {
        super(AuthenticationConfiguration.class, AuthenticatorRegistry.class, DEFAULT, DefaultAuthenticatorRegistry::new);
    }

    @Override
    public AuthenticationConfiguration parseConfiguration(Specification specification, AuthenticatorRegistry registry) throws InvalidSpecificationException {
        try {
            System.out.println(specification.getChilds("authenticators"));
            Map<String, AuthenticationConfiguration.Authenticator> authenticators = new LinkedHashMap<>();
            for (String authenticatorName : specification.getChilds("authenticators")) {
                authenticators.put(authenticatorName, parseAuthenticator(authenticatorName, specification, registry));
            }
            List<AuthenticationConfiguration.Zone> zones = new ArrayList<>();
            for (String zoneName : specification.getChilds("zones")) {
                zones.add(parseZone(zoneName, specification, authenticators));
            }
            Specification handshakeSpecification = MapSpecification.create(specification, "handshake");
            HandshakeConfiguration handshake = ConfigurationProvider.get().parseConfiguration(HandshakeConfiguration.class, handshakeSpecification, registry);
            return AuthenticationConfiguration.create(zones, authenticators, registry, handshake);
        } catch (ConfigurationNotFoundException cause) {
            throw new InvalidSpecificationException(specification, cause);
        }
    }

    private AuthenticationConfiguration.Zone parseZone(String zoneName, Specification specification, Map<String, AuthenticationConfiguration.Authenticator> authenticators) throws SettingNotFoundException, InvalidSettingException {
        LOGGER.debug("Parsing zone: " + zoneName + "...");
        AuthenticationPolicy policy = parsePolicy(specification, specification.getSetting("zones", zoneName, "policy"));
        AuthenticationConfiguration.Authenticator authenticator;
        if (specification.hasSetting("zones", zoneName, "authenticator")) {
            authenticator = parseAuthenticator(specification, specification.getSetting("zones", zoneName, "authenticator"), authenticators);
        } else if (policy == AuthenticationPolicy.NONE) {
            authenticator = null;
        } else {
            throw new SettingNotFoundException(specification, Arrays.asList("zones", zoneName, "authenticator"));
        }
        List<String> endpoints = parseEndpoints(specification, specification.getSetting("zones", zoneName, "endpoints"));
        return new AuthenticationConfiguration.Zone(zoneName, policy, endpoints, authenticator);
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
                throw new InvalidSettingException(specification, setting, "Invalid policy value, must be: none, optional, redirect or required!");
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

    private AuthenticationConfiguration.Authenticator parseAuthenticator(String authenticatorName, Specification specification, AuthenticatorRegistry registry) throws InvalidSpecificationException {
        LOGGER.debug("Parsing authenticator: " + authenticatorName + "...");
        String onFailure;
        if (specification.hasSetting("authenticators", authenticatorName, "onFailure")) {
            onFailure = Specifications.parseString(specification, "authenticators", authenticatorName, "onFailure");
        } else {
            onFailure = null;
        }
        AuthenticationConfiguration.Authenticator authenticator = new AuthenticationConfiguration.Authenticator(
                authenticatorName,
                parseClass(specification, specification.getSetting("authenticators", authenticatorName, "implementation")),
                onFailure,
                parseAuthenticationConfiguration(authenticatorName, specification, registry));
        initializeAuthenticator(specification, authenticator, registry);
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

    private Configuration parseAuthenticationConfiguration(String authenticatorName, Specification specification, AuthenticatorRegistry registry) throws InvalidSpecificationException {
        Specification.Setting configTypeSetting = specification.getSetting("authenticators", authenticatorName, "configuration", "type");
        Class<?> configurationClass = parseClass(specification, configTypeSetting);
        if (!Configuration.class.isAssignableFrom(configurationClass)) {
            throw new InvalidSettingException(specification, configTypeSetting, "Configuration type is not implementing Configuration: " + configTypeSetting.getValue());
        }
        try {
            Specification configSpecification = MapSpecification.create(specification, "authenticators", authenticatorName, "configuration", "settings");
            return ConfigurationProvider.get().parseConfiguration(Types.cast(configurationClass), configSpecification, registry);
        } catch (ConfigurationNotFoundException cause) {
            throw new InvalidSettingException(specification, specification.getSetting("authenticators", authenticatorName, "configuration", "settings"), cause.getCause());
        }
    }

    /*
     * First, looks at a static create(configuration, registry),
     * Second, looks at a static create(configuration),
     * When none found, for a constructor(configuration),
     * otherwise error.
     */
    private void initializeAuthenticator(Specification specification, AuthenticationConfiguration.Authenticator authenticator, AuthenticatorRegistry registry) throws InvalidSpecificationException {
        try {
            LOGGER.debug("Initializing authenticator: " + authenticator.getName());
            Class<? extends Configuration> configClass = authenticator.getConfiguration().getClass();
            Method createConfigRegistryMethod = getPublicStaticCreateMethodOrNull(authenticator, new Class<?>[]{configClass, AuthenticatorRegistry.class});
            Object instance = null;
            if (createConfigRegistryMethod != null) {
                instance = createConfigRegistryMethod.invoke(null, authenticator.getConfiguration(), registry);
            } else {
                Method createConfigMethod = getPublicStaticCreateMethodOrNull(authenticator, new Class<?>[]{configClass});
                if (createConfigMethod != null) {
                    instance = createConfigMethod.invoke(null, authenticator.getConfiguration());
                } else {
                    Constructor<?> constructor = getConstructor(authenticator);
                    if (constructor != null) {
                        instance = constructor.newInstance(authenticator.getConfiguration());
                    }
                }
            }
            if (instance == null) {
                throw new IllegalStateException("No proper create method or constructor found for instantiation of: " + authenticator.getName());
            } else {
                if (instance instanceof HandshakeSession.SessionAware) {
                    ((HandshakeSession.SessionAware) instance).init(HandshakeSessionManager.get());
                }
            }
            registry.register(authenticator.getName(), instance);
        } catch (IllegalAccessException | IllegalStateException | InvocationTargetException | InstantiationException cause) {
            LOGGER.error("Failed to initialize authenticator: " + cause.getMessage());
            throw new InvalidSpecificationException(specification, cause.getMessage(), cause);
        }
    }

    private Method getPublicStaticCreateMethodOrNull(AuthenticationConfiguration.Authenticator authenticator, Class<?>[] parameterTypes) {
        for (Method method : authenticator.getImplementationClass().getMethods()) {
            if (method.getName().equals("create")) {
                if (Arrays.equals(method.getParameterTypes(), parameterTypes)) {
                    if (Modifier.isStatic(method.getModifiers()) && Modifier.isPublic(method.getModifiers())) {
                        return method;
                    }
                }
            }
        }
        return null;
    }

    private Constructor<?> getConstructor(AuthenticationConfiguration.Authenticator authenticator) {
        for (Constructor<?> constructor : authenticator.getImplementationClass().getConstructors()) {
            Type[] parameterTypes = constructor.getGenericParameterTypes();
            for (Type type : parameterTypes) {
                if (type.equals(authenticator.getConfiguration().getClass())) {
                    return constructor;
                }
            }
        }
        return null;
    }
}

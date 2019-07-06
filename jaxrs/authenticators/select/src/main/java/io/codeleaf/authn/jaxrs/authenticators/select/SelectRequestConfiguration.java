package io.codeleaf.authn.jaxrs.authenticators.select;

import io.codeleaf.config.Configuration;

import java.net.URI;
import java.util.Map;

public final class SelectRequestConfiguration implements Configuration {

    private final boolean custom;
    private final URI customPageUrl;
    private final Map<String, Option> options;
    private final String parameterName;

    public SelectRequestConfiguration(boolean custom, URI customPageUrl, Map<String, Option> options, String parameterName) {
        this.custom = custom;
        this.customPageUrl = customPageUrl;
        this.options = options;
        this.parameterName = parameterName;
    }

    public boolean isCustom() {
        return custom;
    }

    public URI getCustomPageUrl() {
        return customPageUrl;
    }

    public Map<String, Option> getOptions() {
        return options;
    }

    public String getParameterName() {
        return parameterName;
    }

    public static class Option {

        private final String authenticatorName;
        private final String label;
        private final URI iconUrl;
        private final boolean enabled;

        public Option(String authenticatorName, String label, URI iconUrl, boolean enabled) {
            this.authenticatorName = authenticatorName;
            this.label = label;
            this.iconUrl = iconUrl;
            this.enabled = enabled;
        }

        public String getAuthenticatorName() {
            return authenticatorName;
        }

        public String getLabel() {
            return label;
        }

        public URI getIconUrl() {
            return iconUrl;
        }

        public boolean isEnabled() {
            return enabled;
        }
    }
}

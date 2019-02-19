package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.jaxrs.spi.HandshakeState;

import javax.ws.rs.container.ContainerRequestContext;
import java.util.LinkedHashMap;
import java.util.Map;

public final class HandshakeSessionManager implements HandshakeSession {

    private static final ThreadLocal<HandshakeState> states = new ThreadLocal<>();
    private static final ThreadLocal<JaxrsRequestAuthenticatorExecutor> executors = new ThreadLocal<>();
    private static final ThreadLocal<ContainerRequestContext> requestContexts = new ThreadLocal<>();
    private static final ThreadLocal<Map<String, Object>> attributes = ThreadLocal.withInitial(LinkedHashMap::new);

    private HandshakeSessionManager() {
    }

    @Override
    public HandshakeState getState() {
        return states.get();
    }

    public void setState(HandshakeState state) {
        states.set(state);
    }

    @Override
    public JaxrsRequestAuthenticatorExecutor getExecutor() {
        return executors.get();
    }

    public void setExecutor(JaxrsRequestAuthenticatorExecutor executor) {
        executors.set(executor);
    }

    @Override
    public ContainerRequestContext getRequestContext() {
        return requestContexts.get();
    }

    public void setRequestContext(ContainerRequestContext requestContext) {
        requestContexts.set(requestContext);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes.get();
    }

    public void clear() {
        states.remove();
        executors.remove();
        requestContexts.remove();
    }

    private static final HandshakeSessionManager INSTANCE = new HandshakeSessionManager();

    public static HandshakeSessionManager get() {
        return INSTANCE;
    }
}

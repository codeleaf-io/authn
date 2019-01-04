package io.codeleaf.authn.jaxrs.basic;


import io.codeleaf.authn.impl.DefaultAuthenticationContext;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

public class BasicSecurityContext extends DefaultAuthenticationContext implements SecurityContext {

    public BasicSecurityContext(Principal principal) {
        super(principal);
    }

    public Principal getUserPrincipal() {
        return getPrincipal();
    }

    public boolean isUserInRole(String role) {
        //TODO: Fix this when we support Authorisation
       return false;
    }

    public String getAuthenticationScheme() {
        return BASIC_AUTH;
    }
}
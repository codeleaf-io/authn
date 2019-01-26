package io.codeleaf.authn.jaxrs;

import java.lang.annotation.*;

@Documented
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface Authentication {
    AuthenticationPolicy value() default AuthenticationPolicy.REQUIRED;
    String authenticator() default "";
}

/*
 * ContainerProxy
 *
 * Copyright (C) 2016-2025 Open Analytics
 *
 * ===========================================================================
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License as published by
 * The Apache Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License
 * along with this program.  If not, see <http://www.apache.org/licenses/>
 */
package eu.openanalytics.containerproxy.auth.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.openanalytics.containerproxy.auth.IAuthenticationBackend;
import eu.openanalytics.containerproxy.auth.impl.msgraph.MicrosoftGraphGroupFetcher;
import eu.openanalytics.containerproxy.auth.impl.oidc.AccessTokenDecoder;
import eu.openanalytics.containerproxy.auth.impl.oidc.OpenIdReAuthorizeFilter;
import eu.openanalytics.containerproxy.spec.expression.SpecExpressionContext;
import eu.openanalytics.containerproxy.spec.expression.SpecExpressionResolver;
import eu.openanalytics.containerproxy.util.ContextPathHelper;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimAccessor;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static eu.openanalytics.containerproxy.auth.impl.oidc.OpenIDConfiguration.REG_ID;

public class OpenIDAuthenticationBackend implements IAuthenticationBackend {

    public static final String NAME = "openid";

    private static final String ENV_TOKEN_NAME = "SHINYPROXY_WEBSERVICE_ACCESS_TOKEN";
    private static OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
    private static AccessTokenDecoder accessTokenDecoder;
    private static final Logger log = LogManager.getLogger(OpenIDAuthenticationBackend.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    @Inject
    private Environment environment;
    @Inject
    private ClientRegistrationRepository clientRegistrationRepo;
    @Inject
    @Lazy
    private SavedRequestAwareAuthenticationSuccessHandler successHandler;
    @Inject
    private OpenIdReAuthorizeFilter openIdReAuthorizeFilter;
    @Inject
    private SpecExpressionResolver specExpressionResolver;
    @Inject
    private ContextPathHelper contextPathHelper;
    @Autowired(required = false)
    private MicrosoftGraphGroupFetcher microsoftGraphGroupFetcher;

    private static OAuth2AuthorizedClient refreshClient(String principalName) {
        return oAuth2AuthorizedClientService.loadAuthorizedClient(REG_ID, principalName);
    }

    @Autowired
    public void setAccessTokenDecoder(AccessTokenDecoder accessTokenDecoder) {
        OpenIDAuthenticationBackend.accessTokenDecoder = accessTokenDecoder;
    }

    @Autowired
    public void setOAuth2AuthorizedClientService(OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
        OpenIDAuthenticationBackend.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public boolean hasAuthorization() {
        return true;
    }

    @Override
    public void configureHttpSecurity(HttpSecurity http) throws Exception {
        http
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .successHandler(successHandler)
                        .clientRegistrationRepository(clientRegistrationRepo)
                        .authorizedClientService(oAuth2AuthorizedClientService)
                        .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                                .authorizationRequestResolver(authorizationRequestResolver()))
                        .failureHandler((request, response, exception) -> {
                            log.error(exception);
                            response.sendRedirect(ServletUriComponentsBuilder
                                    .fromCurrentContextPath()
                                    .path("/auth-error")
                                    .build()
                                    .toUriString());
                        })
                        .userInfoEndpoint(userinfo -> userinfo
                                .oidcUserService(createOidcUserService())))
                .addFilterAfter(openIdReAuthorizeFilter, UsernamePasswordAuthenticationFilter.class);
    }

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver() {
        Boolean usePkce = environment.getProperty("proxy.openid.with-pkce", Boolean.class, false);
        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepo,
                OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);

        if (usePkce) {
            authorizationRequestResolver
                    .setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        }

        return authorizationRequestResolver;
    }

    @Override
    public void configureAuthenticationManagerBuilder(AuthenticationManagerBuilder auth) {
        // Nothing to do.
    }

    public String getLoginRedirectURI() {
        return contextPathHelper.withoutEndingSlash()
                + OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
                + "/" + REG_ID;
    }

    @Override
    public String getLogoutSuccessURL() {
        String logoutURL = environment.getProperty("proxy.openid.logout-url", "/logout-success");
        if (logoutURL == null || logoutURL
                .trim()
                .isEmpty())
            logoutURL = IAuthenticationBackend.super.getLogoutSuccessURL();
        return logoutURL;
    }

    @Override
    public void customizeContainerEnv(Authentication user, Map<String, String> env) {
        OAuth2AuthorizedClient client = refreshClient(user.getName());
        if (client == null || client.getAccessToken() == null)
            return;
        CustomNameOidcUser oidcUser = (CustomNameOidcUser) user.getPrincipal();
        env.put(ENV_TOKEN_NAME, oidcUser.getToken());

        if (!environment.getProperty("proxy.disable-readonly-mode", boolean.class, false)
                && oidcUser.getPermissions().equals("0")) {
            env.put("MIRO_MODE", "readonly");
        }
    }

    @Override
    public LogoutSuccessHandler getLogoutSuccessHandler() {
        return (httpServletRequest, httpServletResponse, authentication) -> {
            String resolvedLogoutUrl;
            if (authentication != null) {
                SpecExpressionContext context = SpecExpressionContext
                        .create(authentication.getPrincipal(), authentication.getCredentials()).build();
                resolvedLogoutUrl = specExpressionResolver.evaluateToString(getLogoutSuccessURL(), context);
            } else {
                resolvedLogoutUrl = getLogoutSuccessURL();
            }

            SimpleUrlLogoutSuccessHandler delegate = new SimpleUrlLogoutSuccessHandler();
            delegate.setDefaultTargetUrl(resolvedLogoutUrl);
            delegate.onLogoutSuccess(httpServletRequest, httpServletResponse, authentication);
        };
    }

    protected OidcUserService createOidcUserService() {
        // Use a custom UserService that supports the 'emails' array attribute.
        return new OidcUserService() {
            @Override
            public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
                OidcUser user;
                try {
                    user = super.loadUser(userRequest);
                } catch (IllegalArgumentException ex) {
                    log.warn("Error while loading user info: {}", ex.getMessage());
                    throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST),
                            "Error while loading user info", ex);
                } catch (OAuth2AuthenticationException ex) {
                    log.warn("Error while loading user info: {}", ex.getMessage());
                    throw ex;
                }

                String nameAttributeKey = environment.getProperty("proxy.openid.username-attribute", "email");

                RestTemplate restTemplate = new RestTemplate();

                HttpHeaders headers = new HttpHeaders();
                headers.setAccept(List.of(MediaType.APPLICATION_JSON));
                headers.setContentType(MediaType.APPLICATION_JSON);

                try {
                    String body = String.format("{\"id_token\": \"%s\"}", user.getIdToken().getTokenValue());
                    String loginUrl = environment.getProperty("proxy.webservice.authentication-url",
                            "http://auth:1234/login") + "/oidc";
                    ResponseEntity<String> result = restTemplate.exchange(loginUrl, HttpMethod.POST,
                            new HttpEntity<>(body, headers), String.class);
                    if (result.getStatusCode() != HttpStatus.OK) {
                        throw new OAuth2AuthenticationException(
                                new OAuth2Error("invalid_response", "Unknown response received " + result, ""));
                    }
                    JsonNode jsonResponse = objectMapper.readTree(result.getBody());
                    SpecExpressionContext context = SpecExpressionContext.create(jsonResponse).build();
                    String token = specExpressionResolver.evaluateToString("#{json.get('token')}", context);
                    String permissions = specExpressionResolver.evaluateToString("#{json.get('permissions')}", context);
                    String username = specExpressionResolver.evaluateToString("#{json.get('username')}", context);

                    Set<GrantedAuthority> authorities = new HashSet<>();
                    List<String> groups = specExpressionResolver.evaluateToList(List.of("#{json.get('roles')}"),
                            context);
                    for (String role : groups) {
                        String mappedRole = role.toUpperCase().startsWith("ROLE_") ? role : "ROLE_" + role;
                        authorities.add(new SimpleGrantedAuthority(mappedRole.toUpperCase()));
                    }
                    return new CustomNameOidcUser(authorities,
                            user.getIdToken(),
                            user.getUserInfo(),
                            nameAttributeKey,
                            username,
                            token,
                            permissions);
                } catch (HttpClientErrorException ex) {
                    throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST),
                            "HttpClientErrorException while trying to log in to Engine", ex);
                } catch (RestClientException ex) {
                    throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST),
                            "RestClientException while trying to log in to Engine", ex);
                } catch (JsonProcessingException ex) {
                    throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST),
                            "JsonProcessingException while trying to log in to Engine", ex);
                }
            }
        };
    }

    public static class CustomNameOidcUser extends DefaultOidcUser {

        private static final long serialVersionUID = 7563253562760236634L;
        private static final String ID_ATTR_EMAILS = "emails";

        private final String customName;
        private final String token;
        private final String permissions;

        public CustomNameOidcUser(Set<GrantedAuthority> authorities, OidcIdToken idToken, OidcUserInfo userInfo,
                String nameAttributeKey,
                String customName, String token, String permissions) {
            super(authorities, idToken, userInfo, nameAttributeKey);
            this.customName = customName;
            this.token = token;
            this.permissions = permissions;
        }

        @Override
        public String getName() {
            return customName;
        }

        public String getToken() {
            return token;
        }

        public String getPermissions() {
            return permissions;
        }

        public String getRefreshToken() {
            OAuth2AuthorizedClient client = refreshClient(getName());
            if (client == null || client.getRefreshToken() == null) {
                return null;
            }
            return client
                    .getRefreshToken()
                    .getTokenValue();
        }

        public String getAccessToken() {
            OAuth2AuthorizedClient client = refreshClient(getName());
            if (client == null || client.getAccessToken() == null) {
                return null;
            }
            return client
                    .getAccessToken()
                    .getTokenValue();
        }

        public Jwt getAccessTokenAsJwt() {
            try {
                return accessTokenDecoder.decode(getAccessToken());
            } catch (JwtException e) {
                log.warn("Failed to decode access token as JWT", e);
                throw e;
            }
        }
    }
}

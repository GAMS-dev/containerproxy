/**
 * ContainerProxy
 *
 * Copyright (C) 2016-2023 Open Analytics
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

import eu.openanalytics.containerproxy.auth.IAuthenticationBackend;
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
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer.AuthorizedUrl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
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
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
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

	private static final String REG_ID = "miroserver";
	private static final String ENV_TOKEN_NAME = "SHINYPROXY_WEBSERVICE_ACCESS_TOKEN";
	
	private final Logger log = LogManager.getLogger(OpenIDAuthenticationBackend.class);
	
	@Inject
	private Environment environment;

	@Inject
	private ClientRegistrationRepository clientRegistrationRepo;

	@Inject
	@Lazy
	private SavedRequestAwareAuthenticationSuccessHandler successHandler;

	private static OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

	@Autowired
	public void setOAuth2AuthorizedClientService(OAuth2AuthorizedClientService oAuth2AuthorizedClientService)  {
		OpenIDAuthenticationBackend.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
	}

	@Inject
	private OpenIdReAuthorizeFilter openIdReAuthorizeFilter;

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public boolean hasAuthorization() {
		return true;
	}
	
	@Override
	public void configureHttpSecurity(HttpSecurity http, AuthorizedUrl anyRequestConfigurer) throws Exception {
		anyRequestConfigurer.authenticated();

		http
			.oauth2Login()
				.loginPage("/login")
				.successHandler(successHandler)
				.clientRegistrationRepository(clientRegistrationRepo)
				.authorizedClientService(oAuth2AuthorizedClientService)
				.authorizationEndpoint()
					.authorizationRequestResolver(authorizationRequestResolver())
				.and()
				.failureHandler(new AuthenticationFailureHandler() {

					@Override
					public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
							AuthenticationException exception) throws IOException, ServletException {
						log.error(exception);
						response.sendRedirect(ServletUriComponentsBuilder.fromCurrentContextPath().path("/auth-error").build().toUriString());
					}
					
				})
				.userInfoEndpoint()
					.oidcUserService(createOidcUserService())
				.and()
			.and()
			.addFilterAfter(openIdReAuthorizeFilter, UsernamePasswordAuthenticationFilter.class);
	}

	private OAuth2AuthorizationRequestResolver authorizationRequestResolver() {
		Boolean usePkce = environment.getProperty("proxy.openid.with-pkce", Boolean.class, false);
		DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepo,
				OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);

		if (usePkce) {
			authorizationRequestResolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
		}

		return authorizationRequestResolver;
	}

	@Override
	public void configureAuthenticationManagerBuilder(AuthenticationManagerBuilder auth) throws Exception {
		// Nothing to do.
	}

	public String getLoginRedirectURI() {
		return ContextPathHelper.withoutEndingSlash()
				+ OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI 
				+ "/" + REG_ID;
	}
	
	@Override
	public String getLogoutSuccessURL() {
		String logoutURL = environment.getProperty("proxy.openid.logout-url", "/logout-success");
		if (logoutURL == null || logoutURL.trim().isEmpty()) logoutURL = IAuthenticationBackend.super.getLogoutSuccessURL();
		return logoutURL;
	}
	
	@Override
	public void customizeContainerEnv(Authentication user, Map<String, String> env) {
		OAuth2AuthorizedClient client = refreshClient(user.getName());
		if (client == null || client.getAccessToken() == null) return;
		CustomNameOidcUser oidcUser = (CustomNameOidcUser) user.getPrincipal();
 		env.put(ENV_TOKEN_NAME, oidcUser.getToken());

		if ( !environment.getProperty("proxy.disable-readonly-mode", boolean.class, false) && oidcUser.getPermissions().equals("0") ) {
			env.put("MIRO_MODE", "readonly");
		}
	}

	@Inject
	private SpecExpressionResolver specExpressionResolver;

	@Override
	public LogoutSuccessHandler getLogoutSuccessHandler() {
		return (httpServletRequest, httpServletResponse, authentication) -> {
			String resolvedLogoutUrl;
			if (authentication != null) {
				SpecExpressionContext context = SpecExpressionContext.create(authentication.getPrincipal(), authentication.getCredentials());
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
					throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "Error while loading user info", ex);
				} catch (OAuth2AuthenticationException ex) {
					log.warn("Error while loading user info: {}", ex.getMessage());
					throw ex;
				}

				String nameAttributeKey = environment.getProperty("proxy.openid.username-attribute", "email");

				RestTemplate restTemplate = new RestTemplate();

				HttpHeaders headers = new HttpHeaders();
				headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
				headers.setContentType(MediaType.APPLICATION_JSON);

				try {
					String body = String.format("{\"id_token\": \"%s\"}", user.getIdToken().getTokenValue());
					String loginUrl = environment.getProperty("proxy.webservice.authentication-url") + "/oidc";
					ResponseEntity<String> result = restTemplate.exchange(loginUrl, HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
					if (result.getStatusCode() != HttpStatus.OK) {
						throw new OAuth2AuthenticationException(new OAuth2Error("invalid_response", "Unknown response received " + result, ""));
					}
					String token = JsonPath.parse(result.getBody()).read("$.token");

					String permissions = "";

					try {
						permissions = JsonPath.parse(result.getBody()).read("$.permissions");
					} catch(PathNotFoundException e) {
						// old versions of auth container might not return this field
					}

					String username = JsonPath.parse(result.getBody()).read("$.username");

					Set<GrantedAuthority> authorities = new HashSet<>();
					List<String> roles = JsonPath.parse(result.getBody()).read("$.roles");
					for (String role: roles) {
						String mappedRole = role.toUpperCase().startsWith("ROLE_") ? role : "ROLE_" + role;
						authorities.add(new SimpleGrantedAuthority(mappedRole.toUpperCase()));
					}
					return new CustomNameOidcUser(authorities,
							user.getIdToken(),
							user.getUserInfo(),
							nameAttributeKey,
							username,
							token,
							permissions
					);
				} catch (HttpClientErrorException ex) {
					throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "HttpClientErrorException while trying to log in to Engine", ex);
				} catch (RestClientException ex) {
					throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "RestClientException while trying to log in to Engine", ex);
				}
			}
		};
	}

	private static OAuth2AuthorizedClient refreshClient(String principalName) {
		return oAuth2AuthorizedClientService.loadAuthorizedClient(REG_ID, principalName);
	}


	public static class CustomNameOidcUser extends DefaultOidcUser {

		private static final long serialVersionUID = 7563253562760236634L;
		private static final String ID_ATTR_EMAILS = "emails";
		
		private final String customName;
		private final String token;
		private final String permissions;

		public CustomNameOidcUser(Set<GrantedAuthority> authorities, OidcIdToken idToken, OidcUserInfo userInfo, String nameAttributeKey,
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
			return client.getRefreshToken().getTokenValue();
		}
	}
}

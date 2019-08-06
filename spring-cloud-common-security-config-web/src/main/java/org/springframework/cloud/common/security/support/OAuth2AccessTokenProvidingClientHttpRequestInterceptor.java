/*
 * Copyright 2018-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.cloud.common.security.support;

import java.io.IOException;

import org.springframework.cloud.common.security.ManualOAuthAuthenticationDetails;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * This implementation of a {@link ClientHttpRequestInterceptor} will retrieve, if available, the OAuth2 Access Token
 * and add it to the {@code Authorization} HTTP header.
 *
 * @author Gunnar Hillert
 */
public class OAuth2AccessTokenProvidingClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

	final String staticOauthAccessToken;

	public OAuth2AccessTokenProvidingClientHttpRequestInterceptor(String staticOauthAccessToken) {
		super();
		Assert.hasText(staticOauthAccessToken, "staticOauthAccessToken must not be null or empty.");
		this.staticOauthAccessToken = staticOauthAccessToken;
	}

	public OAuth2AccessTokenProvidingClientHttpRequestInterceptor() {
		super();
		this.staticOauthAccessToken = null;
	}

	@Override
	public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
			throws IOException {
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		final String token;

		if (StringUtils.hasText(this.staticOauthAccessToken)) {
			token = this.staticOauthAccessToken;
		}
		else if (authentication != null && authentication instanceof OAuth2Authentication) {
			final OAuth2Authentication auth2Authentication = (OAuth2Authentication) authentication;

			if (auth2Authentication.getDetails() instanceof OAuth2AuthenticationDetails) {
				final OAuth2AuthenticationDetails auth2AuthenticationDetails =
					(OAuth2AuthenticationDetails) auth2Authentication.getDetails();
				token = auth2AuthenticationDetails.getTokenValue();
			}
			else if (auth2Authentication.getDetails() instanceof ManualOAuthAuthenticationDetails) {
				ManualOAuthAuthenticationDetails manualOAuthAuthenticationDetails =
					(ManualOAuthAuthenticationDetails) auth2Authentication.getDetails();
				token = manualOAuthAuthenticationDetails.getAccessToken().getValue();
			}
			else {
				token = null;
			}
		}
		else {
			token = null;
		}

		if (token != null) {
			request.getHeaders().add(HttpHeaders.AUTHORIZATION, OAuth2AccessToken.BEARER_TYPE + " " + token);
		}
		return execution.execute(request, body);
	}
}

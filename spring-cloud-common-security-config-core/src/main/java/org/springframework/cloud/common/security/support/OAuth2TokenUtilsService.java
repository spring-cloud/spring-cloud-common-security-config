/*
 * Copyright 2019 the original author or authors.
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

import org.springframework.security.core.Authentication;

/**
 * Service providing OAuth2 Security-related utility methods that may
 * required other Spring Security services.
 *
 * @author Gunnar Hillert
 *
 */
public interface OAuth2TokenUtilsService {

	/**
	 * Retrieves the access token from the {@link Authentication} implementation.
	 *
	 * @return Should never return null.
	 */
	String getAccessTokenOfAuthenticatedUser();

}
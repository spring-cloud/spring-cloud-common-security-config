/*
 * Copyright 2016-2018 the original author or authors.
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

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import javax.validation.constraints.NotNull;

/**
 * Properties for the Ldap security aspects of an application.
 *
 * @author Gunnar Hillert
 * @author Ilayaperumal Gopinathan
 */
@LdapSecurityPropertiesValid
public class LdapSecurityProperties {

	private boolean enabled = false;

	@NotNull(message = "Provide a valid url to your Ldap server")
	private URI url;

	private String userDnPattern;

	private String managerDn;

	private String managerPassword;

	private String userSearchBase = "";

	private String userSearchFilter;

	private String groupSearchFilter = "";

	private String groupSearchBase = "";

	private String groupRoleAttribute = "cn";

	private Map<String, String> roleMappings = new HashMap<>(0);

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public URI getUrl() {
		return url;
	}

	public void setUrl(URI url) {
		this.url = url;
	}

	public String getUserDnPattern() {
		return userDnPattern;
	}

	public void setUserDnPattern(String userDnPattern) {
		this.userDnPattern = userDnPattern;
	}

	public String getManagerDn() {
		return managerDn;
	}

	public void setManagerDn(String managerDn) {
		this.managerDn = managerDn;
	}

	public String getManagerPassword() {
		return managerPassword;
	}

	public void setManagerPassword(String managerPassword) {
		this.managerPassword = managerPassword;
	}

	public String getUserSearchBase() {
		return userSearchBase;
	}

	public void setUserSearchBase(String userSearchBase) {
		this.userSearchBase = userSearchBase;
	}

	public String getUserSearchFilter() {
		return userSearchFilter;
	}

	public void setUserSearchFilter(String userSearchFilter) {
		this.userSearchFilter = userSearchFilter;
	}

	public String getGroupSearchFilter() {
		return groupSearchFilter;
	}

	public void setGroupSearchFilter(String groupSearchFilter) {
		this.groupSearchFilter = groupSearchFilter;
	}

	public String getGroupSearchBase() {
		return groupSearchBase;
	}

	public void setGroupSearchBase(String groupSearchBase) {
		this.groupSearchBase = groupSearchBase;
	}

	public String getGroupRoleAttribute() {
		return groupRoleAttribute;
	}

	public void setGroupRoleAttribute(String groupRoleAttribute) {
		this.groupRoleAttribute = groupRoleAttribute;
	}

	/**
	 * When using Ldap, you can optionally specify a custom mapping of role names
	 * in Ldap to role names as they exist in the Spring application. If not
	 * set, then the roles in Ldap itself must match the role names:
	 *
	 * <ul>
	 *   <li>MANAGE
	 *   <li>VIEW
	 *   <li>CREATE
	 * </ul>
	 *
	 * @return Optional (May be null). Returns a map of role-to-role mappings.
	 */
	public Map<String, String> getRoleMappings() {
		return roleMappings;
	}

}

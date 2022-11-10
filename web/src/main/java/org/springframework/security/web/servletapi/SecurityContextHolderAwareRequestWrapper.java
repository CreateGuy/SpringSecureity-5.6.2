/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.servletapi;

import java.security.Principal;
import java.util.Collection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * A Spring Security-aware <code>HttpServletRequestWrapper</code>, which uses the
 * <code>SecurityContext</code>-defined <code>Authentication</code> object to implement
 * the servlet API security methods:
 *
 * <ul>
 * <li>{@link #getUserPrincipal()}</li>
 * <li>{@link SecurityContextHolderAwareRequestWrapper#isUserInRole(String)}</li>
 * <li>{@link HttpServletRequestWrapper#getRemoteUser()}.</li>
 * </ul>
 *
 * @author Orlando Garcia Carmona
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 * @see SecurityContextHolderAwareRequestFilter
 */
public class SecurityContextHolderAwareRequestWrapper extends HttpServletRequestWrapper {

	/**
	 * 认证对象解析器
	 */
	private final AuthenticationTrustResolver trustResolver;

	/**
	 * 角色前缀
	 */
	private final String rolePrefix;

	/**
	 * Creates a new instance with {@link AuthenticationTrustResolverImpl}.
	 * @param request
	 * @param rolePrefix
	 */
	public SecurityContextHolderAwareRequestWrapper(HttpServletRequest request, String rolePrefix) {
		this(request, new AuthenticationTrustResolverImpl(), rolePrefix);
	}

	/**
	 * Creates a new instance
	 * @param request the original {@link HttpServletRequest}
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
	 * null.
	 * @param rolePrefix The prefix to be added to {@link #isUserInRole(String)} or null
	 * if no prefix.
	 */
	public SecurityContextHolderAwareRequestWrapper(HttpServletRequest request,
			AuthenticationTrustResolver trustResolver, String rolePrefix) {
		super(request);
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		this.rolePrefix = rolePrefix;
		this.trustResolver = trustResolver;
	}

	/**
	 * 获得认证对象
	 * 注意：匿名用户视为未登陆
	 */
	private Authentication getAuthentication() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		return (!this.trustResolver.isAnonymous(auth)) ? auth : null;
	}

	/**
	 * 返回用户名称
	 * 一般情况Principal是UserDetails或者其子类
	 */
	@Override
	public String getRemoteUser() {
		Authentication auth = getAuthentication();
		if ((auth == null) || (auth.getPrincipal() == null)) {
			return null;
		}
		if (auth.getPrincipal() instanceof UserDetails) {
			return ((UserDetails) auth.getPrincipal()).getUsername();
		}
		if (auth instanceof AbstractAuthenticationToken) {
			return auth.getName();
		}
		return auth.getPrincipal().toString();
	}

	/**
	 * 获得认证对象中主体(Principal)
	 * 一般情况都是User或者其子类
	 */
	@Override
	public Principal getUserPrincipal() {
		Authentication auth = getAuthentication();
		if ((auth == null) || (auth.getPrincipal() == null)) {
			return null;
		}
		return auth;
	}

	/**
	 * 判断当前用户是否拥有某个角色
	 * @param role
	 * @return
	 */
	private boolean isGranted(String role) {
		Authentication auth = getAuthentication();
		//添加角色前缀
		if (this.rolePrefix != null && role != null && !role.startsWith(this.rolePrefix)) {
			role = this.rolePrefix + role;
		}
		if ((auth == null) || (auth.getPrincipal() == null)) {
			return false;
		}
		Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
		if (authorities == null) {
			return false;
		}
		for (GrantedAuthority grantedAuthority : authorities) {
			if (role.equals(grantedAuthority.getAuthority())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Simple searches for an exactly matching
	 * {@link org.springframework.security.core.GrantedAuthority#getAuthority()}.
	 * <p>
	 * Will always return <code>false</code> if the <code>SecurityContextHolder</code>
	 * contains an <code>Authentication</code> with <code>null</code>
	 * <code>principal</code> and/or <code>GrantedAuthority[]</code> objects.
	 * @param role the <code>GrantedAuthority</code><code>String</code> representation to
	 * check for
	 * @return <code>true</code> if an <b>exact</b> (case sensitive) matching granted
	 * authority is located, <code>false</code> otherwise
	 */
	@Override
	public boolean isUserInRole(String role) {
		return isGranted(role);
	}

	@Override
	public String toString() {
		return "SecurityContextHolderAwareRequestWrapper[ " + getRequest() + "]";
	}

}

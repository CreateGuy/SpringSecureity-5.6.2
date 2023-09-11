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

import java.io.IOException;
import java.util.List;

import javax.servlet.AsyncContext;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * 对Request包装，让Request也可以进行登录，登出等等功能
 * 这是Servlet3.0出现了Request的登录，登出，所以SpringSecurity也要让Request支持
 */
public class SecurityContextHolderAwareRequestFilter extends GenericFilterBean {

	/**
	 * 角色前缀
	 */
	private String rolePrefix = "ROLE_";

	/**
	 * 包装Request的工厂
	 */
	private HttpServletRequestFactory requestFactory;

	/**
	 * 身份认证入口点，一般是跳转到登录页
	 */
	private AuthenticationEntryPoint authenticationEntryPoint;

	/**
	 * 局部认证管理器，用来做登录的
	 */
	private AuthenticationManager authenticationManager;

	/**
	 * 登出处理器。用来做登出的
	 */
	private List<LogoutHandler> logoutHandlers;

	/**
	 * 认证对象解析器
	 */
	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	public void setRolePrefix(String rolePrefix) {
		Assert.notNull(rolePrefix, "Role prefix must not be null");
		this.rolePrefix = rolePrefix;
		updateFactory();
	}

	/**
	 * <p>
	 * Sets the {@link AuthenticationEntryPoint} used when integrating
	 * {@link HttpServletRequest} with Servlet 3 APIs. Specifically, it will be used when
	 * {@link HttpServletRequest#authenticate(HttpServletResponse)} is called and the user
	 * is not authenticated.
	 * </p>
	 * <p>
	 * If the value is null (default), then the default container behavior will be be
	 * retained when invoking {@link HttpServletRequest#authenticate(HttpServletResponse)}
	 * .
	 * </p>
	 * @param authenticationEntryPoint the {@link AuthenticationEntryPoint} to use when
	 * invoking {@link HttpServletRequest#authenticate(HttpServletResponse)} if the user
	 * is not authenticated.
	 */
	public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	/**
	 * <p>
	 * Sets the {@link AuthenticationManager} used when integrating
	 * {@link HttpServletRequest} with Servlet 3 APIs. Specifically, it will be used when
	 * {@link HttpServletRequest#login(String, String)} is invoked to determine if the
	 * user is authenticated.
	 * </p>
	 * <p>
	 * If the value is null (default), then the default container behavior will be
	 * retained when invoking {@link HttpServletRequest#login(String, String)}.
	 * </p>
	 * @param authenticationManager the {@link AuthenticationManager} to use when invoking
	 * {@link HttpServletRequest#login(String, String)}
	 */
	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	/**
	 * <p>
	 * Sets the {@link LogoutHandler}s used when integrating with
	 * {@link HttpServletRequest} with Servlet 3 APIs. Specifically it will be used when
	 * {@link HttpServletRequest#logout()} is invoked in order to log the user out. So
	 * long as the {@link LogoutHandler}s do not commit the {@link HttpServletResponse}
	 * (expected), then the user is in charge of handling the response.
	 * </p>
	 * <p>
	 * If the value is null (default), the default container behavior will be retained
	 * when invoking {@link HttpServletRequest#logout()}.
	 * </p>
	 * @param logoutHandlers the {@code List&lt;LogoutHandler&gt;}s when invoking
	 * {@link HttpServletRequest#logout()}.
	 */
	public void setLogoutHandlers(List<LogoutHandler> logoutHandlers) {
		this.logoutHandlers = logoutHandlers;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		chain.doFilter(
				//包装Request
				this.requestFactory.create((HttpServletRequest) req
						, (HttpServletResponse) res), res);
	}

	@Override
	public void afterPropertiesSet() throws ServletException {
		super.afterPropertiesSet();
		updateFactory();
	}

	/**
	 * 更新工厂的角色前缀
	 */
	private void updateFactory() {
		String rolePrefix = this.rolePrefix;
		this.requestFactory = createServlet3Factory(rolePrefix);
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. The default is
	 * {@link AuthenticationTrustResolverImpl}.
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
	 * null.
	 */
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		this.trustResolver = trustResolver;
		updateFactory();
	}

	/**
	 * 创建包装工厂
	 * @param rolePrefix
	 * @return
	 */
	private HttpServletRequestFactory createServlet3Factory(String rolePrefix) {
		HttpServlet3RequestFactory factory = new HttpServlet3RequestFactory(rolePrefix);
		factory.setTrustResolver(this.trustResolver);
		factory.setAuthenticationEntryPoint(this.authenticationEntryPoint);
		factory.setAuthenticationManager(this.authenticationManager);
		factory.setLogoutHandlers(this.logoutHandlers);
		return factory;
	}

}

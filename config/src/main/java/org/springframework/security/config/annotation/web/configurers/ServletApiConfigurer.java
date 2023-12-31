/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;

/**
 * 请求包装配置类
 */
public final class ServletApiConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<ServletApiConfigurer<H>, H> {

	private SecurityContextHolderAwareRequestFilter securityContextRequestFilter = new SecurityContextHolderAwareRequestFilter();

	/**
	 * Creates a new instance
	 * @see HttpSecurity#servletApi()
	 */
	public ServletApiConfigurer() {
	}

	public ServletApiConfigurer<H> rolePrefix(String rolePrefix) {
		this.securityContextRequestFilter.setRolePrefix(rolePrefix);
		return this;
	}

	@Override
	@SuppressWarnings("unchecked")
	public void configure(H http) {
		//设置局部认证管理器
		this.securityContextRequestFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));

		//设置身份认证入口点
		ExceptionHandlingConfigurer<H> exceptionConf = http.getConfigurer(ExceptionHandlingConfigurer.class);
		AuthenticationEntryPoint authenticationEntryPoint = (exceptionConf != null)
				? exceptionConf.getAuthenticationEntryPoint(http) : null;
		this.securityContextRequestFilter.setAuthenticationEntryPoint(authenticationEntryPoint);

		//设置登出处理器
		LogoutConfigurer<H> logoutConf = http.getConfigurer(LogoutConfigurer.class);
		List<LogoutHandler> logoutHandlers = (logoutConf != null) ? logoutConf.getLogoutHandlers() : null;
		this.securityContextRequestFilter.setLogoutHandlers(logoutHandlers);

		//设置认证对象解析器
		AuthenticationTrustResolver trustResolver = http.getSharedObject(AuthenticationTrustResolver.class);
		if (trustResolver != null) {
			this.securityContextRequestFilter.setTrustResolver(trustResolver);
		}

		//设置角色前缀
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		if (context != null) {
			String[] grantedAuthorityDefaultsBeanNames = context.getBeanNamesForType(GrantedAuthorityDefaults.class);
			if (grantedAuthorityDefaultsBeanNames.length == 1) {
				GrantedAuthorityDefaults grantedAuthorityDefaults = context
						.getBean(grantedAuthorityDefaultsBeanNames[0], GrantedAuthorityDefaults.class);
				this.securityContextRequestFilter.setRolePrefix(grantedAuthorityDefaults.getRolePrefix());
			}
		}
		this.securityContextRequestFilter = postProcess(this.securityContextRequestFilter);
		http.addFilter(this.securityContextRequestFilter);
	}

}

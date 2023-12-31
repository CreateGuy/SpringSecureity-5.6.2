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

package org.springframework.security.web.authentication.rememberme;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * 记住我功能的登录
 */
public class RememberMeAuthenticationFilter extends GenericFilterBean implements ApplicationEventPublisherAware {

	/**
	 * 事件推送器
	 */
	private ApplicationEventPublisher eventPublisher;

	/**
	 * 认证成功处理器
	 */
	private AuthenticationSuccessHandler successHandler;

	/**
	 * 局部认证管理器
	 */
	private AuthenticationManager authenticationManager;

	/**
	 * 记住我服务
	 */
	private RememberMeServices rememberMeServices;

	public RememberMeAuthenticationFilter(AuthenticationManager authenticationManager,
			RememberMeServices rememberMeServices) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(rememberMeServices, "rememberMeServices cannot be null");
		this.authenticationManager = authenticationManager;
		this.rememberMeServices = rememberMeServices;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.authenticationManager, "authenticationManager must be specified");
		Assert.notNull(this.rememberMeServices, "rememberMeServices must be specified");
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	/**
	 * 进行记住我方式的认证
	 * @param request
	 * @param response
	 * @param chain
	 * @throws IOException
	 * @throws ServletException
	 */
	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//如果HttpSession级别的安全上下文中有认证对象的话，那就说明已经认证过了，就不需要进行记住我方式认证了
		//通常情况是因为Session过期了
		//注意：匿名认证过滤器在这个过滤器的后面
		if (SecurityContextHolder.getContext().getAuthentication() != null) {
			this.logger.debug(LogMessage
					.of(() -> "SecurityContextHolder not populated with remember-me token, as it already contained: '"
							+ SecurityContextHolder.getContext().getAuthentication() + "'"));
			chain.doFilter(request, response);
			return;
		}
		//获得认证对象
		Authentication rememberMeAuth = this.rememberMeServices.autoLogin(request, response);
		if (rememberMeAuth != null) {
			try {
				//通过局部认证管理器进行认证操作
				//局部认证管理器通常有匿名和记住我的认证提供者，而全局认证管理器才有表单的认证提供者
				rememberMeAuth = this.authenticationManager.authenticate(rememberMeAuth);

				//将认证对象保存到线程级别的安全上下文策略中
				SecurityContext context = SecurityContextHolder.createEmptyContext();
				context.setAuthentication(rememberMeAuth);
				SecurityContextHolder.setContext(context);

				//执行认证成功的方法，默认是空方法
				onSuccessfulAuthentication(request, response, rememberMeAuth);
				this.logger.debug(LogMessage.of(() -> "SecurityContextHolder populated with remember-me token: '"
						+ SecurityContextHolder.getContext().getAuthentication() + "'"));

				//推送交互式认证成功事件
				if (this.eventPublisher != null) {
					this.eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
							SecurityContextHolder.getContext().getAuthentication(), this.getClass()));
				}

				//执行认证成功处理器
				if (this.successHandler != null) {
					this.successHandler.onAuthenticationSuccess(request, response, rememberMeAuth);
					return;
				}
			}
			catch (AuthenticationException ex) {
				this.logger.debug(LogMessage
						.format("SecurityContextHolder not populated with remember-me token, as AuthenticationManager "
								+ "rejected Authentication returned by RememberMeServices: '%s'; "
								+ "invalidating remember-me token", rememberMeAuth),
						ex);
				//执行认证失败操作
				this.rememberMeServices.loginFail(request, response);
				//默认空方法
				onUnsuccessfulAuthentication(request, response, ex);
			}
		}
		chain.doFilter(request, response);
	}

	/**
	 * 通过记住我令牌进行认证通过了，就调用此方法
	 */
	protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			Authentication authResult) {
	}

	/**
	 * Called if the {@code AuthenticationManager} rejects the authentication object
	 * returned from the {@code RememberMeServices} {@code autoLogin} method. This method
	 * will not be called when no remember-me token is present in the request and
	 * {@code autoLogin} reurns null.
	 */
	protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) {
	}

	public RememberMeServices getRememberMeServices() {
		return this.rememberMeServices;
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
		this.eventPublisher = eventPublisher;
	}

	/**
	 * Allows control over the destination a remembered user is sent to when they are
	 * successfully authenticated. By default, the filter will just allow the current
	 * request to proceed, but if an {@code AuthenticationSuccessHandler} is set, it will
	 * be invoked and the {@code doFilter()} method will return immediately, thus allowing
	 * the application to redirect the user to a specific URL, regardless of whatthe
	 * original request was for.
	 * @param successHandler the strategy to invoke immediately before returning from
	 * {@code doFilter()}.
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler successHandler) {
		Assert.notNull(successHandler, "successHandler cannot be null");
		this.successHandler = successHandler;
	}

}

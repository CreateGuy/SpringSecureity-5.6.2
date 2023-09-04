/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.session;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * 检测从执行 SecurityContextPersistenceFilter 到执行本过滤器之间是否就已经通过身份验证
 * 如果已经通过，那么就执行HttpSession认证策略，和检查HttpSession是否已经无效
 */
public class SessionManagementFilter extends GenericFilterBean {

	/**
	 * 表明当前请求是否已经执行过当前过滤器的标志位
	 */
	static final String FILTER_APPLIED = "__spring_security_session_mgmt_filter_applied";

	/**
	 * HttpSession级别的安全上下文存储策略
	 */
	private final SecurityContextRepository securityContextRepository;

	/**
	 * HttpSession认证策略
	 */
	private SessionAuthenticationStrategy sessionAuthenticationStrategy;

	/**
	 * 认证对象解析器
	 */
	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	/**
	 * HttpSession过期(无效)策略
	 */
	private InvalidSessionStrategy invalidSessionStrategy = null;

	/**
	 * 执行HttpSession认证策略抛出异常，执行的失败策略
	 */
	private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

	public SessionManagementFilter(SecurityContextRepository securityContextRepository) {
		this(securityContextRepository, new SessionFixationProtectionStrategy());
	}

	public SessionManagementFilter(SecurityContextRepository securityContextRepository,
			SessionAuthenticationStrategy sessionStrategy) {
		Assert.notNull(securityContextRepository, "SecurityContextRepository cannot be null");
		Assert.notNull(sessionStrategy, "SessionAuthenticationStrategy cannot be null");
		this.securityContextRepository = securityContextRepository;
		this.sessionAuthenticationStrategy = sessionStrategy;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (request.getAttribute(FILTER_APPLIED) != null) {
			chain.doFilter(request, response);
			return;
		}
		//标记为当前request已经执行过
		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
		//没有在HttpSession级别安全上下文策略找到安全上下文
		if (!this.securityContextRepository.containsContext(request)) {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			//但是在线程级别安全上下文策略中找到，并且是一个不是一个匿名用户
			//比如通过rememberMe登录的，因为
			if (authentication != null && !this.trustResolver.isAnonymous(authentication)) {
				//用户在当前请求中已经通过身份验证，因此调用HttpSession认证策略
				//比如说rememberMe的方法进行登录，因为RememberMeAuthenticationFilter在SecurityContextPersistenceFilter之前，在本过滤器之后执行
				try {
					//执行HttpSession认证策略
					this.sessionAuthenticationStrategy.onAuthentication(authentication, request, response);
				}
				catch (SessionAuthenticationException ex) {
					//会话策略可以拒绝认证，比如说并发会话可能会抛出异常
					this.logger.debug("SessionAuthenticationStrategy rejected the authentication object", ex);
					//清空线程级别的安全上下文
					SecurityContextHolder.clearContext();
					//执行失败策略
					this.failureHandler.onAuthenticationFailure(request, response, ex);
					return;
				}
				//紧急在HttpSession级别的安全上下文存储策略中保存一个空的安全上下文
				//我猜是通过记住我认证的时候没有将SecurityContext保存在SecurityContextRepository中，所以这里紧急保存下
				this.securityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response);
			}
			else {
				//没有安全上下文或者是一个匿名用户的时候，检查会话过期(无效)
				if (request.getRequestedSessionId() != null && !request.isRequestedSessionIdValid()) {
					if (this.logger.isDebugEnabled()) {
						this.logger.debug(LogMessage.format("Request requested invalid session id %s",
								request.getRequestedSessionId()));
					}
					if (this.invalidSessionStrategy != null) {
						//执行HttpSession过期(无效)策略
						this.invalidSessionStrategy.onInvalidSessionDetected(request, response);
						return;
					}
				}
			}
		}
		chain.doFilter(request, response);
	}

	/**
	 * Sets the strategy which will be invoked instead of allowing the filter chain to
	 * proceed, if the user agent requests an invalid session ID. If the property is not
	 * set, no action will be taken.
	 * @param invalidSessionStrategy the strategy to invoke. Typically a
	 * {@link SimpleRedirectInvalidSessionStrategy}.
	 */
	public void setInvalidSessionStrategy(InvalidSessionStrategy invalidSessionStrategy) {
		this.invalidSessionStrategy = invalidSessionStrategy;
	}

	/**
	 * The handler which will be invoked if the <tt>AuthenticatedSessionStrategy</tt>
	 * raises a <tt>SessionAuthenticationException</tt>, indicating that the user is not
	 * allowed to be authenticated for this session (typically because they already have
	 * too many sessions open).
	 *
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
		Assert.notNull(failureHandler, "failureHandler cannot be null");
		this.failureHandler = failureHandler;
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
	}

}

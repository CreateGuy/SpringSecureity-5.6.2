/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.web.authentication.preauth;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * <ul>
 *     <li>
 *         首先是一个基类：用于处理已经在外部系统进行过认证的身份认证过滤器，其中假定主体(principal)已经由外部系统进行了身份认证
 *     </li>
 *     <li>
 *         这样做的目的只是从请求中提取有关主体的必要信息，而不是对它们进行身份认证。外部身份认证系统可以通过预先身份认证系统从Head或cookie中提取用户们和密码。假定外部系统负责数据的准确性和防止伪造值的提交
 *     </li>
 * </ul>
 * <p>
 */
public abstract class AbstractPreAuthenticatedProcessingFilter extends GenericFilterBean
		implements ApplicationEventPublisherAware {

	/**
	 * 事件推送器
	 */
	private ApplicationEventPublisher eventPublisher = null;

	/**
	 * 认证信息详情源
	 */
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	/**
	 * 一般是是自己设置的局部认证管理器
	 */
	private AuthenticationManager authenticationManager = null;

	/**
	 * 认证失败是否抛出异常
	 */
	private boolean continueFilterChainOnUnsuccessfulAuthentication = true;

	/**
	 * 当预先认证过滤器已经执行过一次后，当前系统就会为其分配本系统的认证对象，
	 * 这样后面执行当前过滤器的时候，就由这个标志位来确保是否检查用户名发送了变化
	 */
	private boolean checkForPrincipalChanges;

	/**
	 * 当用户名发送了变化的是否，是否使其原Session无效
	 */
	private boolean invalidateSessionOnPrincipalChange = true;

	/**
	 * 认证成功处理器
	 */
	private AuthenticationSuccessHandler authenticationSuccessHandler = null;

	/**
	 * 认证失败处理器
	 */
	private AuthenticationFailureHandler authenticationFailureHandler = null;

	/**
	 * 请求匹配器：此时用于确定是否是认证请求
	 */
	private RequestMatcher requiresAuthenticationRequestMatcher = new PreAuthenticatedProcessingRequestMatcher();

	/**
	 * Check whether all required properties have been set.
	 */
	@Override
	public void afterPropertiesSet() {
		try {
			super.afterPropertiesSet();
		}
		catch (ServletException ex) {
			// convert to RuntimeException for passivity on afterPropertiesSet signature
			throw new RuntimeException(ex);
		}
		Assert.notNull(this.authenticationManager, "An AuthenticationManager must be set");
	}

	/**
	 * Try to authenticate a pre-authenticated user with Spring Security if the user has
	 * not yet been authenticated.
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//确定是否是一个认证请求
		if (this.requiresAuthenticationRequestMatcher.matches((HttpServletRequest) request)) {
			if (logger.isDebugEnabled()) {
				logger.debug(LogMessage
						.of(() -> "Authenticating " + SecurityContextHolder.getContext().getAuthentication()));
			}
			//尝试认证
			doAuthenticate((HttpServletRequest) request, (HttpServletResponse) response);
		}
		else {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Did not authenticate since request did not match [%s]",
						this.requiresAuthenticationRequestMatcher));
			}
		}
		chain.doFilter(request, response);
	}

	/**
	 * 确认用户名是否发生了变化
	 * @param request
	 * @param currentAuthentication
	 * @return
	 */
	protected boolean principalChanged(HttpServletRequest request, Authentication currentAuthentication) {
		//通常情况下这是获取用户名
		Object principal = getPreAuthenticatedPrincipal(request);
		//确认用户名是否发生了变化
		if ((principal instanceof String) && currentAuthentication.getName().equals(principal)) {
			return false;
		}
		//确认用户名是否发生了变化
		if (principal != null && principal.equals(currentAuthentication.getPrincipal())) {
			return false;
		}
		this.logger.debug(LogMessage.format("Pre-authenticated principal has changed to %s and will be reauthenticated",
				principal));
		return true;
	}

	/**
	 * 为预认证的用户创建实际的认证对象
	 */
	private void doAuthenticate(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		//获得用户名
		Object principal = getPreAuthenticatedPrincipal(request);
		if (principal == null) {
			this.logger.debug("No pre-authenticated principal found in request");
			return;
		}
		this.logger.debug(LogMessage.format("preAuthenticatedPrincipal = %s, trying to authenticate", principal));
		//获得密码
		Object credentials = getPreAuthenticatedCredentials(request);
		try {
			//封装成功认证对象，然后调用认证管理器进行认证
			PreAuthenticatedAuthenticationToken authenticationRequest = new PreAuthenticatedAuthenticationToken(
					principal, credentials);
			authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
			Authentication authenticationResult = this.authenticationManager.authenticate(authenticationRequest);

			//执行认证成功的操作
			successfulAuthentication(request, response, authenticationResult);
		}
		catch (AuthenticationException ex) {
			//认证失败的处理流程
			unsuccessfulAuthentication(request, response, ex);
			if (!this.continueFilterChainOnUnsuccessfulAuthentication) {
				throw ex;
			}
		}
	}

	/**
	 * 执行认证成功的操作
	 * @param request
	 * @param response
	 * @param authResult
	 * @throws IOException
	 * @throws ServletException
	 */
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			Authentication authResult) throws IOException, ServletException {
		this.logger.debug(LogMessage.format("Authentication success: %s", authResult));
		//设置认证对象到线程级别的安全上下文中
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authResult);
		SecurityContextHolder.setContext(context);

		//推送交互认证成功的事件
		if (this.eventPublisher != null) {
			this.eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
		}

		//执行认证成功处理器
		if (this.authenticationSuccessHandler != null) {
			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authResult);
		}
	}

	/**
	 * 认证失败的处理流程
	 */
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		SecurityContextHolder.clearContext();
		this.logger.debug("Cleared security context due to exception", failed);
		request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, failed);
		if (this.authenticationFailureHandler != null) {
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, failed);
		}
	}

	/**
	 * @param anApplicationEventPublisher The ApplicationEventPublisher to use
	 */
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher anApplicationEventPublisher) {
		this.eventPublisher = anApplicationEventPublisher;
	}

	/**
	 * @param authenticationDetailsSource The AuthenticationDetailsSource to use
	 */
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	protected AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
		return this.authenticationDetailsSource;
	}

	/**
	 * @param authenticationManager The AuthenticationManager to use
	 */
	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	/**
	 * If set to {@code true} (the default), any {@code AuthenticationException} raised by
	 * the {@code AuthenticationManager} will be swallowed, and the request will be
	 * allowed to proceed, potentially using alternative authentication mechanisms. If
	 * {@code false}, authentication failure will result in an immediate exception.
	 * @param shouldContinue set to {@code true} to allow the request to proceed after a
	 * failed authentication.
	 */
	public void setContinueFilterChainOnUnsuccessfulAuthentication(boolean shouldContinue) {
		this.continueFilterChainOnUnsuccessfulAuthentication = shouldContinue;
	}

	/**
	 * If set, the pre-authenticated principal will be checked on each request and
	 * compared against the name of the current <tt>Authentication</tt> object. A check to
	 * determine if {@link Authentication#getPrincipal()} is equal to the principal will
	 * also be performed. If a change is detected, the user will be reauthenticated.
	 * @param checkForPrincipalChanges
	 */
	public void setCheckForPrincipalChanges(boolean checkForPrincipalChanges) {
		this.checkForPrincipalChanges = checkForPrincipalChanges;
	}

	/**
	 * If <tt>checkForPrincipalChanges</tt> is set, and a change of principal is detected,
	 * determines whether any existing session should be invalidated before proceeding to
	 * authenticate the new principal.
	 * @param invalidateSessionOnPrincipalChange <tt>false</tt> to retain the existing
	 * session. Defaults to <tt>true</tt>.
	 */
	public void setInvalidateSessionOnPrincipalChange(boolean invalidateSessionOnPrincipalChange) {
		this.invalidateSessionOnPrincipalChange = invalidateSessionOnPrincipalChange;
	}

	/**
	 * Sets the strategy used to handle a successful authentication.
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the strategy used to handle a failed authentication.
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	/**
	 * Sets the request matcher to check whether to proceed the request further.
	 */
	public void setRequiresAuthenticationRequestMatcher(RequestMatcher requiresAuthenticationRequestMatcher) {
		Assert.notNull(requiresAuthenticationRequestMatcher, "requestMatcher cannot be null");
		this.requiresAuthenticationRequestMatcher = requiresAuthenticationRequestMatcher;
	}

	/**
	 * 获取Principal，此时一般是用户名
	 */
	protected abstract Object getPreAuthenticatedPrincipal(HttpServletRequest request);

	/**
	 * 获取密码
	 * @param request
	 * @return
	 */
	protected abstract Object getPreAuthenticatedCredentials(HttpServletRequest request);

	/**
	 * Request matcher for default auth check logic
	 */
	private class PreAuthenticatedProcessingRequestMatcher implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
			//如果没有认证对象，就视为是认证请求
			if (currentUser == null) {
				return true;
			}
			//是否检查用户名发送了变化
			if (!AbstractPreAuthenticatedProcessingFilter.this.checkForPrincipalChanges) {
				return false;
			}
			//确认用户名是否发生了变化
			if (!principalChanged(request, currentUser)) {
				return false;
			}

			//到这就说明用户名发送了变化
			AbstractPreAuthenticatedProcessingFilter.this.logger
					.debug("Pre-authenticated principal has changed and will be reauthenticated");

			//是否清除Session
			if (AbstractPreAuthenticatedProcessingFilter.this.invalidateSessionOnPrincipalChange) {
				SecurityContextHolder.clearContext();
				HttpSession session = request.getSession(false);
				if (session != null) {
					AbstractPreAuthenticatedProcessingFilter.this.logger.debug("Invalidating existing session");
					//使原Session无效
					session.invalidate();
					//重新创建新的
					request.getSession();
				}
			}
			return true;
		}

	}

}

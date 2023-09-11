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

package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

/**
 * 出现认证异常而执行的失败策略
 * 使用场景1：执行HttpSession认证策略抛出了异常，然后就有可能执行此方法(需配置)
 */
public class SimpleUrlAuthenticationFailureHandler implements AuthenticationFailureHandler {

	protected final Log logger = LogFactory.getLog(getClass());

	/**
	 * 默认跳转的Url
	 */
	private String defaultFailureUrl;

	/**
	 * 是转发还重定向
	 */
	private boolean forwardToDestination = false;

	/**
	 * 是否在HttpSession中保存抛出异常的原因
	 */
	private boolean allowSessionCreation = true;

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public SimpleUrlAuthenticationFailureHandler() {
	}

	public SimpleUrlAuthenticationFailureHandler(String defaultFailureUrl) {
		setDefaultFailureUrl(defaultFailureUrl);
	}

	/**
	 * 如果没有设置错误的Url就返回401错误码
	 * 如果设置了错误的Url，再判断是重定向还是转发，将调用saveException来缓存异常以便在目标视图中使用。
	 */
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		if (this.defaultFailureUrl == null) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Sending 401 Unauthorized error since no failure URL is set");
			}
			else {
				this.logger.debug("Sending 401 Unauthorized error");
			}
			response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
			return;
		}
		saveException(request, exception);
		if (this.forwardToDestination) {
			this.logger.debug("Forwarding to " + this.defaultFailureUrl);
			request.getRequestDispatcher(this.defaultFailureUrl).forward(request, response);
		}
		else {
			this.redirectStrategy.sendRedirect(request, response, this.defaultFailureUrl);
		}
	}

	/**
	 * 在Request或者HttpSession中保存认证异常
	 * If {@code forwardToDestination} is set to true, request scope will be used,
	 * otherwise it will attempt to store the exception in the session. If there is no
	 * session and {@code allowSessionCreation} is {@code true} a session will be created.
	 * Otherwise the exception will not be stored.
	 */
	protected final void saveException(HttpServletRequest request, AuthenticationException exception) {
		//如果是转发，那么是同一个Request，保存在Request就好了
		if (this.forwardToDestination) {
			request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
			return;
		}
		//是重定向，没办法只有保存到HttpSession中
		HttpSession session = request.getSession(false);
		if (session != null || this.allowSessionCreation) {
			request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
		}
	}

	/**
	 * The URL which will be used as the failure destination.
	 * @param defaultFailureUrl the failure URL, for example "/loginFailed.jsp".
	 */
	public void setDefaultFailureUrl(String defaultFailureUrl) {
		Assert.isTrue(UrlUtils.isValidRedirectUrl(defaultFailureUrl),
				() -> "'" + defaultFailureUrl + "' is not a valid redirect URL");
		this.defaultFailureUrl = defaultFailureUrl;
	}

	protected boolean isUseForward() {
		return this.forwardToDestination;
	}

	/**
	 * If set to <tt>true</tt>, performs a forward to the failure destination URL instead
	 * of a redirect. Defaults to <tt>false</tt>.
	 */
	public void setUseForward(boolean forwardToDestination) {
		this.forwardToDestination = forwardToDestination;
	}

	/**
	 * Allows overriding of the behaviour when redirecting to a target URL.
	 */
	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}

	protected RedirectStrategy getRedirectStrategy() {
		return this.redirectStrategy;
	}

	protected boolean isAllowSessionCreation() {
		return this.allowSessionCreation;
	}

	public void setAllowSessionCreation(boolean allowSessionCreation) {
		this.allowSessionCreation = allowSessionCreation;
	}

}

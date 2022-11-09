/*
 * Copyright 2002-2019 the original author or authors.
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
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * 限制并发会话的过滤器
 * <ul>
 *     <li>
 *         作用1：对于已经过期的SessionInformation进行登出操作，然后执行过期策略
 *     </li>
 *     <li>
 *         作用2：更新操作时间，这是因为如果并发数达到限制，可能会根据最后操作时间来踢出用户
 *     </li>
 * </ul>
 */
public class ConcurrentSessionFilter extends GenericFilterBean {

	/**
	 * SessionInformation注册中心
	 */
	private final SessionRegistry sessionRegistry;

	/**
	 * 出现SessionInformation过期，需要执行的策略
	 * 和下面那个的作用一样
	 */
	private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;

	/**
	 * 出现SessionInformation过期，需要重定向的Url
	 */
	private String expiredUrl;

	/**
	 * 重定向逻辑，和上面那个一起使用
	 */
	private RedirectStrategy redirectStrategy;

	/**
	 * 登出需要执行的处理器：是通过LogoutConfigurer拿到的
	 */
	private LogoutHandler handlers = new CompositeLogoutHandler(new SecurityContextLogoutHandler());


	public ConcurrentSessionFilter(SessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "SessionRegistry required");
		this.sessionRegistry = sessionRegistry;
		//创建默认的SessionInformation过期策略
		this.sessionInformationExpiredStrategy = new ResponseBodySessionInformationExpiredStrategy();
	}

	/**
	 * Creates a new instance
	 * @param sessionRegistry the SessionRegistry to use
	 * @param expiredUrl the URL to redirect to
	 * @deprecated use
	 * {@link #ConcurrentSessionFilter(SessionRegistry, SessionInformationExpiredStrategy)}
	 * with {@link SimpleRedirectSessionInformationExpiredStrategy} instead.
	 */
	@Deprecated
	public ConcurrentSessionFilter(SessionRegistry sessionRegistry, String expiredUrl) {
		Assert.notNull(sessionRegistry, "SessionRegistry required");
		Assert.isTrue(expiredUrl == null || UrlUtils.isValidRedirectUrl(expiredUrl),
				() -> expiredUrl + " isn't a valid redirect URL");
		this.expiredUrl = expiredUrl;
		this.sessionRegistry = sessionRegistry;
		this.sessionInformationExpiredStrategy = (event) -> {
			HttpServletRequest request = event.getRequest();
			HttpServletResponse response = event.getResponse();
			SessionInformation info = event.getSessionInformation();
			this.redirectStrategy.sendRedirect(request, response, determineExpiredUrl(request, info));
		};
	}

	public ConcurrentSessionFilter(SessionRegistry sessionRegistry,
			SessionInformationExpiredStrategy sessionInformationExpiredStrategy) {
		Assert.notNull(sessionRegistry, "sessionRegistry required");
		Assert.notNull(sessionInformationExpiredStrategy, "sessionInformationExpiredStrategy cannot be null");
		this.sessionRegistry = sessionRegistry;
		this.sessionInformationExpiredStrategy = sessionInformationExpiredStrategy;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.sessionRegistry, "SessionRegistry required");
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	/**
	 * <ul>
	 *     <li>
	 *         判断SessionInformation是否过期
	 *     </li>
	 *     <li>
	 *         SessionInformation的过期通常是由 HttpSession认证策略的 ConcurrentSessionControlAuthenticationStrategy 导致的
	 *     </li>
	 * </ul>
	 * @param request
	 * @param response
	 * @param chain
	 * @throws IOException
	 * @throws ServletException
	 */
	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpSession session = request.getSession(false);
		if (session != null) {
			//获得当前会话对应的SessionInformation
			SessionInformation info = this.sessionRegistry.getSessionInformation(session.getId());
			if (info != null) {
				//如果过期了
				if (info.isExpired()) {
					// Expired - abort processing
					this.logger.debug(LogMessage
							.of(() -> "Requested session ID " + request.getRequestedSessionId() + " has expired."));
					//执行登出操作
					doLogout(request, response);
					//执行SessionInformation过期策略
					this.sessionInformationExpiredStrategy
							.onExpiredSessionDetected(new SessionInformationExpiredEvent(info, request, response));
					return;
				}
				//如果没有过期，那么就更新操作时间
				//这是因为如果并发数达到限制，可能会根据最后操作时间来踢出用户
				this.sessionRegistry.refreshLastRequest(info.getSessionId());
			}
		}
		chain.doFilter(request, response);
	}

	/**
	 * Determine the URL for expiration
	 * @param request the HttpServletRequest
	 * @param info the {@link SessionInformation}
	 * @return the URL for expiration
	 * @deprecated Use
	 * {@link #ConcurrentSessionFilter(SessionRegistry, SessionInformationExpiredStrategy)}
	 * instead.
	 */
	@Deprecated
	protected String determineExpiredUrl(HttpServletRequest request, SessionInformation info) {
		return this.expiredUrl;
	}

	/**
	 * 执行登出操作
	 * @param request
	 * @param response
	 */
	private void doLogout(HttpServletRequest request, HttpServletResponse response) {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		this.handlers.logout(request, response, auth);
	}

	public void setLogoutHandlers(LogoutHandler[] handlers) {
		this.handlers = new CompositeLogoutHandler(handlers);
	}

	/**
	 * Set list of {@link LogoutHandler}
	 * @param handlers list of {@link LogoutHandler}
	 * @since 5.2.0
	 */
	public void setLogoutHandlers(List<LogoutHandler> handlers) {
		this.handlers = new CompositeLogoutHandler(handlers);
	}

	/**
	 * Sets the {@link RedirectStrategy} used with
	 * {@link #ConcurrentSessionFilter(SessionRegistry, String)}
	 * @param redirectStrategy the {@link RedirectStrategy} to use
	 * @deprecated use
	 * {@link #ConcurrentSessionFilter(SessionRegistry, SessionInformationExpiredStrategy)}
	 * instead.
	 */
	@Deprecated
	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}

	/**
	 * SessionInformation过期执行的策略，就是往响应体写入数据
	 */
	private static final class ResponseBodySessionInformationExpiredStrategy
			implements SessionInformationExpiredStrategy {

		@Override
		public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException {
			HttpServletResponse response = event.getResponse();
			response.getWriter().print("This session has been expired (possibly due to multiple concurrent "
					+ "logins being attempted as the same user).");
			response.flushBuffer();
		}

	}

}

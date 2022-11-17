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

package org.springframework.security.web.authentication.logout;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Logs a principal out.
 * <p>
 * Polls a series of {@link LogoutHandler}s. The handlers should be specified in the order
 * they are required. Generally you will want to call logout handlers
 * <code>TokenBasedRememberMeServices</code> and <code>SecurityContextLogoutHandler</code>
 * (in that order).
 * <p>
 * After logout, a redirect will be performed to the URL determined by either the
 * configured <tt>LogoutSuccessHandler</tt> or the <tt>logoutSuccessUrl</tt>, depending on
 * which constructor was used.
 *
 * @author Ben Alex
 * @author Eddú Meléndez
 */
public class LogoutFilter extends GenericFilterBean {

	/**
	 * 请求匹配器：用于判断是否是登出请求
	 */
	private RequestMatcher logoutRequestMatcher;

	/**
	 * 登出处理器
	 */
	private final LogoutHandler handler;

	/**
	 * 登出成功处理器
	 */
	private final LogoutSuccessHandler logoutSuccessHandler;

	/**
	 * Constructor which takes a <tt>LogoutSuccessHandler</tt> instance to determine the
	 * target destination after logging out. The list of <tt>LogoutHandler</tt>s are
	 * intended to perform the actual logout functionality (such as clearing the security
	 * context, invalidating the session, etc.).
	 */
	public LogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler... handlers) {
		this.handler = new CompositeLogoutHandler(handlers);
		Assert.notNull(logoutSuccessHandler, "logoutSuccessHandler cannot be null");
		this.logoutSuccessHandler = logoutSuccessHandler;
		setFilterProcessesUrl("/logout");
	}

	public LogoutFilter(String logoutSuccessUrl, LogoutHandler... handlers) {
		this.handler = new CompositeLogoutHandler(handlers);
		Assert.isTrue(!StringUtils.hasLength(logoutSuccessUrl) || UrlUtils.isValidRedirectUrl(logoutSuccessUrl),
				() -> logoutSuccessUrl + " isn't a valid redirect URL");
		SimpleUrlLogoutSuccessHandler urlLogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
		if (StringUtils.hasText(logoutSuccessUrl)) {
			//可以看到即使传入的是Url也会变成登出成功处理器
			urlLogoutSuccessHandler.setDefaultTargetUrl(logoutSuccessUrl);
		}
		this.logoutSuccessHandler = urlLogoutSuccessHandler;
		setFilterProcessesUrl("/logout");
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//判断是否是登出请求
		if (requiresLogout(request, response)) {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Logging out [%s]", auth));
			}
			//先执行登出处理器
			this.handler.logout(request, response, auth);
			//再执行登出成功处理器
			this.logoutSuccessHandler.onLogoutSuccess(request, response, auth);
			return;
		}
		chain.doFilter(request, response);
	}

	/**
	 * 判断是否是登出请求
	 */
	protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
		if (this.logoutRequestMatcher.matches(request)) {
			return true;
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Did not match request to %s", this.logoutRequestMatcher));
		}
		return false;
	}

	public void setLogoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		Assert.notNull(logoutRequestMatcher, "logoutRequestMatcher cannot be null");
		this.logoutRequestMatcher = logoutRequestMatcher;
	}

	public void setFilterProcessesUrl(String filterProcessesUrl) {
		this.logoutRequestMatcher = new AntPathRequestMatcher(filterProcessesUrl);
	}

}

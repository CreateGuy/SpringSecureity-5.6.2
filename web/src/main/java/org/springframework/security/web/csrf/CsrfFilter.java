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

package org.springframework.security.web.csrf;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * <p>
 * Applies
 * <a href="https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)" >CSRF</a>
 * protection using a synchronizer token pattern. Developers are required to ensure that
 * {@link CsrfFilter} is invoked for any request that allows state to change. Typically
 * this just means that they should ensure their web application follows proper REST
 * semantics (i.e. do not change state with the HTTP methods GET, HEAD, TRACE, OPTIONS).
 * </p>
 *
 * <p>
 * Typically the {@link CsrfTokenRepository} implementation chooses to store the
 * {@link CsrfToken} in {@link HttpSession} with {@link HttpSessionCsrfTokenRepository}
 * wrapped by a {@link LazyCsrfTokenRepository}. This is preferred to storing the token in
 * a cookie which can be modified by a client application.
 * </p>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class CsrfFilter extends OncePerRequestFilter {

	/**
	 * 默认的请求匹配器，用于表示是否需要CsRE保护。默认是忽略GET, HEAD, TRACE, OPTIONS这四种，而处理所有其他请求
	 */
	public static final RequestMatcher DEFAULT_CSRF_MATCHER = new DefaultRequiresCsrfMatcher();

	/**
	 * The attribute name to use when marking a given request as one that should not be
	 * filtered.
	 *
	 * To use, set the attribute on your {@link HttpServletRequest}: <pre>
	 * 	CsrfFilter.skipRequest(request);
	 * </pre>
	 */
	private static final String SHOULD_NOT_FILTER = "SHOULD_NOT_FILTER" + CsrfFilter.class.getName();

	private final Log logger = LogFactory.getLog(getClass());

	/**
	 * CsrfToken的存储策略
	 */
	private final CsrfTokenRepository tokenRepository;

	/**
	 * 请求匹配器：不需要进行Csrf校验的
	 */
	private RequestMatcher requireCsrfProtectionMatcher = DEFAULT_CSRF_MATCHER;

	/**
	 * 访问被拒绝处理器
	 */
	private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();

	public CsrfFilter(CsrfTokenRepository csrfTokenRepository) {
		Assert.notNull(csrfTokenRepository, "csrfTokenRepository cannot be null");
		this.tokenRepository = csrfTokenRepository;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		return Boolean.TRUE.equals(request.getAttribute(SHOULD_NOT_FILTER));
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		request.setAttribute(HttpServletResponse.class.getName(), response);
		// 从存储策略中读取令牌
		CsrfToken csrfToken = this.tokenRepository.loadToken(request);
		boolean missingToken = (csrfToken == null);
		// 如果没有先生成后保存
		if (missingToken) {
			csrfToken = this.tokenRepository.generateToken(request);
			this.tokenRepository.saveToken(csrfToken, request, response);
		}

		// 在请求域中暴露Csrf令牌
		request.setAttribute(CsrfToken.class.getName(), csrfToken);
		request.setAttribute(csrfToken.getParameterName(), csrfToken);

		// 判断是否是不需要Csrf保护的
		if (!this.requireCsrfProtectionMatcher.matches(request)) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Did not protect against CSRF since request did not match "
						+ this.requireCsrfProtectionMatcher);
			}
			filterChain.doFilter(request, response);
			return;
		}

		// 从请求头和QueryString中提取Csrf令牌
		String actualToken = request.getHeader(csrfToken.getHeaderName());
		if (actualToken == null) {
			actualToken = request.getParameter(csrfToken.getParameterName());
		}

		// 常数比较令牌是否相同
		if (!equalsConstantTime(csrfToken.getToken(), actualToken)) {
			this.logger.debug(
					LogMessage.of(() -> "Invalid CSRF token found for " + UrlUtils.buildFullRequestUrl(request)));
			AccessDeniedException exception = (!missingToken) ? new InvalidCsrfTokenException(csrfToken, actualToken)
					: new MissingCsrfTokenException(actualToken);
			// 当成访问被拒绝处理
			this.accessDeniedHandler.handle(request, response, exception);
			return;
		}
		// Csrf校验通过
		filterChain.doFilter(request, response);
	}

	public static void skipRequest(HttpServletRequest request) {
		request.setAttribute(SHOULD_NOT_FILTER, Boolean.TRUE);
	}

	/**
	 * Specifies a {@link RequestMatcher} that is used to determine if CSRF protection
	 * should be applied. If the {@link RequestMatcher} returns true for a given request,
	 * then CSRF protection is applied.
	 *
	 * <p>
	 * The default is to apply CSRF protection for any HTTP method other than GET, HEAD,
	 * TRACE, OPTIONS.
	 * </p>
	 * @param requireCsrfProtectionMatcher the {@link RequestMatcher} used to determine if
	 * CSRF protection should be applied.
	 */
	public void setRequireCsrfProtectionMatcher(RequestMatcher requireCsrfProtectionMatcher) {
		Assert.notNull(requireCsrfProtectionMatcher, "requireCsrfProtectionMatcher cannot be null");
		this.requireCsrfProtectionMatcher = requireCsrfProtectionMatcher;
	}

	/**
	 * Specifies a {@link AccessDeniedHandler} that should be used when CSRF protection
	 * fails.
	 *
	 * <p>
	 * The default is to use AccessDeniedHandlerImpl with no arguments.
	 * </p>
	 * @param accessDeniedHandler the {@link AccessDeniedHandler} to use
	 */
	public void setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		Assert.notNull(accessDeniedHandler, "accessDeniedHandler cannot be null");
		this.accessDeniedHandler = accessDeniedHandler;
	}

	/**
	 * 常数时间比较，防止定时攻击
	 * @param expected
	 * @param actual
	 * @return
	 */
	private static boolean equalsConstantTime(String expected, String actual) {
		if (expected == actual) {
			return true;
		}
		if (expected == null || actual == null) {
			return false;
		}
		// Encode after ensure that the string is not null
		byte[] expectedBytes = Utf8.encode(expected);
		byte[] actualBytes = Utf8.encode(actual);
		return MessageDigest.isEqual(expectedBytes, actualBytes);
	}

	/**
	 * 默认的请求匹配器，用于表示是否需要CsRE保护。默认是忽略GET, HEAD, TRACE, OPTIONS这四种，而处理所有其他请求
	 */
	private static final class DefaultRequiresCsrfMatcher implements RequestMatcher {

		private final HashSet<String> allowedMethods = new HashSet<>(Arrays.asList("GET", "HEAD", "TRACE", "OPTIONS"));

		@Override
		public boolean matches(HttpServletRequest request) {
			return !this.allowedMethods.contains(request.getMethod());
		}

		@Override
		public String toString() {
			return "CsrfNotRequired " + this.allowedMethods;
		}

	}

}

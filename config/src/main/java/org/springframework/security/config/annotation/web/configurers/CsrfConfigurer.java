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

package org.springframework.security.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.DelegatingAccessDeniedHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.LazyCsrfTokenRepository;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.session.InvalidSessionAccessDeniedHandler;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * {@link CsrfFilter} 的配置类
 */
public final class CsrfConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<CsrfConfigurer<H>, H> {

	/**
	 * Csrf令牌的默认存储策略
	 */
	private CsrfTokenRepository csrfTokenRepository = new LazyCsrfTokenRepository(new HttpSessionCsrfTokenRepository());

	/**
	 * 不需要Csrf保护的请求方式
	 */
	private RequestMatcher requireCsrfProtectionMatcher = CsrfFilter.DEFAULT_CSRF_MATCHER;

	/**
	 * 不需要Csrf保护的请求地址
	 */
	private List<RequestMatcher> ignoredCsrfProtectionMatchers = new ArrayList<>();

	/**
	 * 需要暴露给 {@code SessionManagementConfigurer} 的认证成功会话策略
	 * <p>如果没有设置默认是一个有关Csrf令牌的，这样认证成功后就会设置令牌的</p>
	 */
	private SessionAuthenticationStrategy sessionAuthenticationStrategy;

	private final ApplicationContext context;

	/**
	 * Creates a new instance
	 * @see HttpSecurity#csrf()
	 */
	public CsrfConfigurer(ApplicationContext context) {
		this.context = context;
	}

	/**
	 * Specify the {@link CsrfTokenRepository} to use. The default is an
	 * {@link HttpSessionCsrfTokenRepository} wrapped by {@link LazyCsrfTokenRepository}.
	 * @param csrfTokenRepository the {@link CsrfTokenRepository} to use
	 * @return the {@link CsrfConfigurer} for further customizations
	 */
	public CsrfConfigurer<H> csrfTokenRepository(CsrfTokenRepository csrfTokenRepository) {
		Assert.notNull(csrfTokenRepository, "csrfTokenRepository cannot be null");
		this.csrfTokenRepository = csrfTokenRepository;
		return this;
	}

	/**
	 * Specify the {@link RequestMatcher} to use for determining when CSRF should be
	 * applied. The default is to ignore GET, HEAD, TRACE, OPTIONS and process all other
	 * requests.
	 * @param requireCsrfProtectionMatcher the {@link RequestMatcher} to use
	 * @return the {@link CsrfConfigurer} for further customizations
	 */
	public CsrfConfigurer<H> requireCsrfProtectionMatcher(RequestMatcher requireCsrfProtectionMatcher) {
		Assert.notNull(requireCsrfProtectionMatcher, "requireCsrfProtectionMatcher cannot be null");
		this.requireCsrfProtectionMatcher = requireCsrfProtectionMatcher;
		return this;
	}

	/**
	 * <p>
	 * Allows specifying {@link HttpServletRequest} that should not use CSRF Protection
	 * even if they match the {@link #requireCsrfProtectionMatcher(RequestMatcher)}.
	 * </p>
	 *
	 * <p>
	 * For example, the following configuration will ensure CSRF protection ignores:
	 * </p>
	 * <ul>
	 * <li>Any GET, HEAD, TRACE, OPTIONS (this is the default)</li>
	 * <li>We also explicitly state to ignore any request that starts with "/sockjs/"</li>
	 * </ul>
	 *
	 * <pre>
	 * http
	 *     .csrf()
	 *         .ignoringAntMatchers("/sockjs/**")
	 *         .and()
	 *     ...
	 * </pre>
	 *
	 * @since 4.0
	 */
	public CsrfConfigurer<H> ignoringAntMatchers(String... antPatterns) {
		return new IgnoreCsrfProtectionRegistry(this.context).antMatchers(antPatterns).and();
	}

	/**
	 * <p>
	 * Allows specifying {@link HttpServletRequest}s that should not use CSRF Protection
	 * even if they match the {@link #requireCsrfProtectionMatcher(RequestMatcher)}.
	 * </p>
	 *
	 * <p>
	 * For example, the following configuration will ensure CSRF protection ignores:
	 * </p>
	 * <ul>
	 * <li>Any GET, HEAD, TRACE, OPTIONS (this is the default)</li>
	 * <li>We also explicitly state to ignore any request that has a "X-Requested-With:
	 * XMLHttpRequest" header</li>
	 * </ul>
	 *
	 * <pre>
	 * http
	 *     .csrf()
	 *         .ignoringRequestMatchers((request) -&gt; "XMLHttpRequest".equals(request.getHeader("X-Requested-With")))
	 *         .and()
	 *     ...
	 * </pre>
	 *
	 * @since 5.1
	 */
	public CsrfConfigurer<H> ignoringRequestMatchers(RequestMatcher... requestMatchers) {
		return new IgnoreCsrfProtectionRegistry(this.context).requestMatchers(requestMatchers).and();
	}

	/**
	 * <p>
	 * Specify the {@link SessionAuthenticationStrategy} to use. The default is a
	 * {@link CsrfAuthenticationStrategy}.
	 * </p>
	 * @param sessionAuthenticationStrategy the {@link SessionAuthenticationStrategy} to
	 * use
	 * @return the {@link CsrfConfigurer} for further customizations
	 * @since 5.2
	 */
	public CsrfConfigurer<H> sessionAuthenticationStrategy(
			SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		Assert.notNull(sessionAuthenticationStrategy, "sessionAuthenticationStrategy cannot be null");
		this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
		return this;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void configure(H http) {
		CsrfFilter filter = new CsrfFilter(this.csrfTokenRepository);

		// 设置不需要Csrf保护的请求对应的请求匹配器
		RequestMatcher requireCsrfProtectionMatcher = getRequireCsrfProtectionMatcher();
		if (requireCsrfProtectionMatcher != null) {
			filter.setRequireCsrfProtectionMatcher(requireCsrfProtectionMatcher);
		}

		// 设置访问被拒绝处理器
		AccessDeniedHandler accessDeniedHandler = createAccessDeniedHandler(http);
		if (accessDeniedHandler != null) {
			filter.setAccessDeniedHandler(accessDeniedHandler);
		}

		// 给 LogoutConfigurer 中设置Csrf存储策略
		// 是为了在登出的时候清除Csrf令牌
		LogoutConfigurer<H> logoutConfigurer = http.getConfigurer(LogoutConfigurer.class);
		if (logoutConfigurer != null) {
			logoutConfigurer.addLogoutHandler(new CsrfLogoutHandler(this.csrfTokenRepository));
		}

		// 给 sessionConfigurer 中认证成功后的会话策略
		// 是为了在认证成功后创建Csrf令牌
		SessionManagementConfigurer<H> sessionConfigurer = http.getConfigurer(SessionManagementConfigurer.class);
		if (sessionConfigurer != null) {
			sessionConfigurer.addSessionAuthenticationStrategy(getSessionAuthenticationStrategy());
		}
		filter = postProcess(filter);
		http.addFilter(filter);
	}

	/**
	 * 返回不需要Csrf保护的请求对应的请求匹配器
	 */
	private RequestMatcher getRequireCsrfProtectionMatcher() {
		if (this.ignoredCsrfProtectionMatchers.isEmpty()) {
			return this.requireCsrfProtectionMatcher;
		}
		return new AndRequestMatcher(this.requireCsrfProtectionMatcher,
				new NegatedRequestMatcher(new OrRequestMatcher(this.ignoredCsrfProtectionMatchers)));
	}

	/**
	 * 通过 {@code ExceptionHandlingConfigurer} 拿到访问被拒绝处理器
	 */
	@SuppressWarnings("unchecked")
	private AccessDeniedHandler getDefaultAccessDeniedHandler(H http) {
		ExceptionHandlingConfigurer<H> exceptionConfig = http.getConfigurer(ExceptionHandlingConfigurer.class);
		AccessDeniedHandler handler = null;
		if (exceptionConfig != null) {
			handler = exceptionConfig.getAccessDeniedHandler();
		}
		if (handler == null) {
			handler = new AccessDeniedHandlerImpl();
		}
		return handler;
	}

	/**
	 * 通过 {@code SessionManagementConfigurer} 拿到 HttpSession过期策略
	 */
	@SuppressWarnings("unchecked")
	private InvalidSessionStrategy getInvalidSessionStrategy(H http) {
		SessionManagementConfigurer<H> sessionManagement = http.getConfigurer(SessionManagementConfigurer.class);
		if (sessionManagement == null) {
			return null;
		}
		return sessionManagement.getInvalidSessionStrategy();
	}

	/**
	 * 创建访问被拒绝处理器
	 */
	private AccessDeniedHandler createAccessDeniedHandler(H http) {
		// 拿到 HttpSession过期策略
		InvalidSessionStrategy invalidSessionStrategy = getInvalidSessionStrategy(http);
		// 拿到访问被拒绝处理器
		AccessDeniedHandler defaultAccessDeniedHandler = getDefaultAccessDeniedHandler(http);
		if (invalidSessionStrategy == null) {
			return defaultAccessDeniedHandler;
		}
		InvalidSessionAccessDeniedHandler invalidSessionDeniedHandler = new InvalidSessionAccessDeniedHandler(
				invalidSessionStrategy);
		LinkedHashMap<Class<? extends AccessDeniedException>, AccessDeniedHandler> handlers = new LinkedHashMap<>();
		handlers.put(MissingCsrfTokenException.class, invalidSessionDeniedHandler);
		return new DelegatingAccessDeniedHandler(handlers, defaultAccessDeniedHandler);
	}

	/**
	 * 创建认证成功后的会话策略
	 */
	private SessionAuthenticationStrategy getSessionAuthenticationStrategy() {
		if (this.sessionAuthenticationStrategy != null) {
			return this.sessionAuthenticationStrategy;
		}
		return new CsrfAuthenticationStrategy(this.csrfTokenRepository);
	}

	/**
	 * 允许注册应该被忽略的Url的注册中心
	 */
	private class IgnoreCsrfProtectionRegistry extends AbstractRequestMatcherRegistry<IgnoreCsrfProtectionRegistry> {

		IgnoreCsrfProtectionRegistry(ApplicationContext context) {
			setApplicationContext(context);
		}

		@Override
		public MvcMatchersIgnoreCsrfProtectionRegistry mvcMatchers(HttpMethod method, String... mvcPatterns) {
			List<MvcRequestMatcher> mvcMatchers = createMvcMatchers(method, mvcPatterns);
			CsrfConfigurer.this.ignoredCsrfProtectionMatchers.addAll(mvcMatchers);
			return new MvcMatchersIgnoreCsrfProtectionRegistry(getApplicationContext(), mvcMatchers);
		}

		@Override
		public MvcMatchersIgnoreCsrfProtectionRegistry mvcMatchers(String... mvcPatterns) {
			return mvcMatchers(null, mvcPatterns);
		}

		CsrfConfigurer<H> and() {
			return CsrfConfigurer.this;
		}

		@Override
		protected IgnoreCsrfProtectionRegistry chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			CsrfConfigurer.this.ignoredCsrfProtectionMatchers.addAll(requestMatchers);
			return this;
		}

	}

	/**
	 * An {@link IgnoreCsrfProtectionRegistry} that allows optionally configuring the
	 * {@link MvcRequestMatcher#setMethod(HttpMethod)}
	 *
	 * @author Rob Winch
	 */
	private final class MvcMatchersIgnoreCsrfProtectionRegistry extends IgnoreCsrfProtectionRegistry {

		private final List<MvcRequestMatcher> mvcMatchers;

		private MvcMatchersIgnoreCsrfProtectionRegistry(ApplicationContext context,
				List<MvcRequestMatcher> mvcMatchers) {
			super(context);
			this.mvcMatchers = mvcMatchers;
		}

		IgnoreCsrfProtectionRegistry servletPath(String servletPath) {
			for (MvcRequestMatcher matcher : this.mvcMatchers) {
				matcher.setServletPath(servletPath);
			}
			return this;
		}

	}

}

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

package org.springframework.security.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.GenericApplicationListenerAdapter;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * 会话管理配置类
 * 安全过滤器填充以下过滤器
 * <ul>
 * <li>{@link SessionManagementFilter}</li>
 * <li>{@link ConcurrentSessionFilter} if there are restrictions on how many concurrent
 */
public final class SessionManagementConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<SessionManagementConfigurer<H>, H> {

	/**
	 * 会话固定身份验证策略
	 */
	private final SessionAuthenticationStrategy DEFAULT_SESSION_FIXATION_STRATEGY = createDefaultSessionFixationProtectionStrategy();

	/**
	 * 默认的HttpSession认证策略
	 * 实际上也由public的set方法可以改变
	 */
	private SessionAuthenticationStrategy sessionFixationAuthenticationStrategy = this.DEFAULT_SESSION_FIXATION_STRATEGY;

	/**
	 * 最后将各个地方的HttpSession证策略组合在一起的 session认证策略
	 * 是{@link CompositeSessionAuthenticationStrategy}
	 */
	private SessionAuthenticationStrategy sessionAuthenticationStrategy;

	/**
	 * 这个和下面这个都有Public的set方法，是让用户设置HttpSession认证策略
	 * 但是这个和sessionFixationAuthenticationStrategy有冲突
	 */
	private SessionAuthenticationStrategy providedSessionAuthenticationStrategy;

	private List<SessionAuthenticationStrategy> sessionAuthenticationStrategies = new ArrayList<>();

	/**
	 * HttpSession过期(无效)策略
	 */
	private InvalidSessionStrategy invalidSessionStrategy;

	/**
	 * HttpSession过期(无效)之后跳转的Url
	 * 就是创建一个跳转的策略
	 */
	private String invalidSessionUrl;

	/**
	 * SessionInformation过期策略
	 */
	private SessionInformationExpiredStrategy expiredSessionStrategy;

	/**
	 * SessionInformation过期之后跳转的Url
	 * 就是创建一个跳转的策略
	 */
	private String expiredUrl;

	/**
	 * SessionInformation注册中心
	 */
	private SessionRegistry sessionRegistry;

	/**
	 * 限制用户会话并发数
	 */
	private Integer maximumSessions;

	/**
	 * 某个用户的会话数达到maximumSessions的时候，是否阻止登录
	 * <ul>
	 *     <li>
	 * 			true: 后面登录的用户直接抛出异常
	 *     </li>
	 *     <li>
	 *			false：将最先登录的那个会话对应的SessionInformation直接设置为已过期，那么遇到ConcurrentSessionFilter就会有对应的退出操作了
	 *     </li>
	 * </ul>
	 */
	private boolean maxSessionsPreventsLogin;

	/**
	 * SpringSecurity创建session的策略
	 */
	private SessionCreationPolicy sessionPolicy;

	private boolean enableSessionUrlRewriting;

	/**
	 * 在执行HttpSession认证策略的时候出现异常执行的处理器
	 * 和下面这个一样
	 */
	private AuthenticationFailureHandler sessionAuthenticationFailureHandler;

	/**
	 * 在执行HttpSession认证策略的时候出现异常跳转了Url
	 * 就是创建一个跳转的策略
	 */
	private String sessionAuthenticationErrorUrl;

	/**
	 * Creates a new instance
	 * @see HttpSecurity#sessionManagement()
	 */
	public SessionManagementConfigurer() {
	}

	/**
	 * Setting this attribute will inject the {@link SessionManagementFilter} with a
	 * {@link SimpleRedirectInvalidSessionStrategy} configured with the attribute value.
	 * When an invalid session ID is submitted, the strategy will be invoked, redirecting
	 * to the configured URL.
	 * @param invalidSessionUrl the URL to redirect to when an invalid session is detected
	 * @return the {@link SessionManagementConfigurer} for further customization
	 */
	public SessionManagementConfigurer<H> invalidSessionUrl(String invalidSessionUrl) {
		this.invalidSessionUrl = invalidSessionUrl;
		return this;
	}

	/**
	 * Setting this attribute will inject the provided invalidSessionStrategy into the
	 * {@link SessionManagementFilter}. When an invalid session ID is submitted, the
	 * strategy will be invoked, redirecting to the configured URL.
	 * @param invalidSessionStrategy the strategy to use when an invalid session ID is
	 * submitted.
	 * @return the {@link SessionManagementConfigurer} for further customization
	 */
	public SessionManagementConfigurer<H> invalidSessionStrategy(InvalidSessionStrategy invalidSessionStrategy) {
		Assert.notNull(invalidSessionStrategy, "invalidSessionStrategy");
		this.invalidSessionStrategy = invalidSessionStrategy;
		return this;
	}

	/**
	 * Defines the URL of the error page which should be shown when the
	 * SessionAuthenticationStrategy raises an exception. If not set, an unauthorized
	 * (402) error code will be returned to the client. Note that this attribute doesn't
	 * apply if the error occurs during a form-based login, where the URL for
	 * authentication failure will take precedence.
	 * @param sessionAuthenticationErrorUrl the URL to redirect to
	 * @return the {@link SessionManagementConfigurer} for further customization
	 */
	public SessionManagementConfigurer<H> sessionAuthenticationErrorUrl(String sessionAuthenticationErrorUrl) {
		this.sessionAuthenticationErrorUrl = sessionAuthenticationErrorUrl;
		return this;
	}

	/**
	 * Defines the {@code AuthenticationFailureHandler} which will be used when the
	 * SessionAuthenticationStrategy raises an exception. If not set, an unauthorized
	 * (402) error code will be returned to the client. Note that this attribute doesn't
	 * apply if the error occurs during a form-based login, where the URL for
	 * authentication failure will take precedence.
	 * @param sessionAuthenticationFailureHandler the handler to use
	 * @return the {@link SessionManagementConfigurer} for further customization
	 */
	public SessionManagementConfigurer<H> sessionAuthenticationFailureHandler(
			AuthenticationFailureHandler sessionAuthenticationFailureHandler) {
		this.sessionAuthenticationFailureHandler = sessionAuthenticationFailureHandler;
		return this;
	}

	/**
	 * If set to true, allows HTTP sessions to be rewritten in the URLs when using
	 * {@link HttpServletResponse#encodeRedirectURL(String)} or
	 * {@link HttpServletResponse#encodeURL(String)}, otherwise disallows HTTP sessions to
	 * be included in the URL. This prevents leaking information to external domains.
	 * @param enableSessionUrlRewriting true if should allow the JSESSIONID to be
	 * rewritten into the URLs, else false (default)
	 * @return the {@link SessionManagementConfigurer} for further customization
	 * @see HttpSessionSecurityContextRepository#setDisableUrlRewriting(boolean)
	 */
	public SessionManagementConfigurer<H> enableSessionUrlRewriting(boolean enableSessionUrlRewriting) {
		this.enableSessionUrlRewriting = enableSessionUrlRewriting;
		return this;
	}

	/**
	 * 设置SpringSecurity创建session的策略
	 * @param sessionCreationPolicy
	 * @return
	 */
	public SessionManagementConfigurer<H> sessionCreationPolicy(SessionCreationPolicy sessionCreationPolicy) {
		Assert.notNull(sessionCreationPolicy, "sessionCreationPolicy cannot be null");
		this.sessionPolicy = sessionCreationPolicy;
		return this;
	}

	/**
	 * Allows explicitly specifying the {@link SessionAuthenticationStrategy}. The default
	 * is to use {@link ChangeSessionIdAuthenticationStrategy}. If restricting the maximum
	 * number of sessions is configured, then
	 * {@link CompositeSessionAuthenticationStrategy} delegating to
	 * {@link ConcurrentSessionControlAuthenticationStrategy}, the default OR supplied
	 * {@code SessionAuthenticationStrategy} and
	 * {@link RegisterSessionAuthenticationStrategy}.
	 *
	 * <p>
	 * NOTE: Supplying a custom {@link SessionAuthenticationStrategy} will override the
	 * default session fixation strategy.
	 * @param sessionAuthenticationStrategy
	 * @return the {@link SessionManagementConfigurer} for further customizations
	 */
	public SessionManagementConfigurer<H> sessionAuthenticationStrategy(
			SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		this.providedSessionAuthenticationStrategy = sessionAuthenticationStrategy;
		return this;
	}

	/**
	 * Adds an additional {@link SessionAuthenticationStrategy} to be used within the
	 * {@link CompositeSessionAuthenticationStrategy}.
	 * @param sessionAuthenticationStrategy
	 * @return the {@link SessionManagementConfigurer} for further customizations
	 */
	SessionManagementConfigurer<H> addSessionAuthenticationStrategy(
			SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		this.sessionAuthenticationStrategies.add(sessionAuthenticationStrategy);
		return this;
	}

	/**
	 * 返回一个防止固定会话攻击的配置类
	 * 通常是用来 通过配置类设置外部配置类的属性
	 */
	public SessionFixationConfigurer sessionFixation() {
		return new SessionFixationConfigurer();
	}

	/**
	 * Allows configuring session fixation protection.
	 * @param sessionFixationCustomizer the {@link Customizer} to provide more options for
	 * the {@link SessionFixationConfigurer}
	 * @return the {@link SessionManagementConfigurer} for further customizations
	 */
	public SessionManagementConfigurer<H> sessionFixation(
			Customizer<SessionFixationConfigurer> sessionFixationCustomizer) {
		sessionFixationCustomizer.customize(new SessionFixationConfigurer());
		return this;
	}

	/**
	 * Controls the maximum number of sessions for a user. The default is to allow any
	 * number of users.
	 * @param maximumSessions the maximum number of sessions for a user
	 * @return the {@link SessionManagementConfigurer} for further customizations
	 */
	public ConcurrencyControlConfigurer maximumSessions(int maximumSessions) {
		this.maximumSessions = maximumSessions;
		return new ConcurrencyControlConfigurer();
	}

	/**
	 * Controls the maximum number of sessions for a user. The default is to allow any
	 * number of users.
	 * @param sessionConcurrencyCustomizer the {@link Customizer} to provide more options
	 * for the {@link ConcurrencyControlConfigurer}
	 * @return the {@link SessionManagementConfigurer} for further customizations
	 */
	public SessionManagementConfigurer<H> sessionConcurrency(
			Customizer<ConcurrencyControlConfigurer> sessionConcurrencyCustomizer) {
		sessionConcurrencyCustomizer.customize(new ConcurrencyControlConfigurer());
		return this;
	}

	/**
	 * Invokes {@link #postProcess(Object)} and sets the
	 * {@link SessionAuthenticationStrategy} for session fixation.
	 * @param sessionFixationAuthenticationStrategy
	 */
	private void setSessionFixationAuthenticationStrategy(
			SessionAuthenticationStrategy sessionFixationAuthenticationStrategy) {
		//与providedSessionAuthenticationStrategy的区别是会多执行postProcess方法
		this.sessionFixationAuthenticationStrategy = postProcess(sessionFixationAuthenticationStrategy);
	}

	@Override
	public void init(H http) {
		//获得安全上下文存储库
		SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
		//判断是否完全不需要创建session
		boolean stateless = isStateless();
		if (securityContextRepository == null) {
			if (stateless) {
				//如果没有安全上下文存储库，又不需要创建session
				//那么就将安全上下文存储库设置为NullSecurityContextRepository
				//那么程序在执行的时候就无法判断当前用户的认证信息了
				http.setSharedObject(SecurityContextRepository.class, new NullSecurityContextRepository());
			}
			else {
				//默认安全上下文存储库的策略是基于HttpSession的
				HttpSessionSecurityContextRepository httpSecurityRepository = new HttpSessionSecurityContextRepository();
				httpSecurityRepository.setDisableUrlRewriting(!this.enableSessionUrlRewriting);
				httpSecurityRepository.setAllowSessionCreation(isAllowSessionCreation());
				//设置认证对象分析器
				AuthenticationTrustResolver trustResolver = http.getSharedObject(AuthenticationTrustResolver.class);
				if (trustResolver != null) {
					httpSecurityRepository.setTrustResolver(trustResolver);
				}
				//将HttpSession级别的安全上下文策略保存到SharedObject中
				http.setSharedObject(SecurityContextRepository.class, httpSecurityRepository);
			}
		}
		//从SharedObject中获取请求缓冲器
		RequestCache requestCache = http.getSharedObject(RequestCache.class);
		if (requestCache == null) {
			//如果没有请求缓冲器并且又不需要创建HttpSession，那就注入一个空实现的请求缓冲器
			//因为请求缓冲器的有效实现类只有HttpSessionRequestCache和CookieRequestCache
			//CookieRequestCache不需要存储在服务端，而HttpSessionRequestCache是基于HttpSession,没有HttpSession也就不用请求缓冲器了
			if (stateless) {
				http.setSharedObject(RequestCache.class, new NullRequestCache());
			}
		}
		//设置HttpSession认证策略
		http.setSharedObject(SessionAuthenticationStrategy.class, getSessionAuthenticationStrategy(http));
		//设置HttpSession过期(无效)策略
		http.setSharedObject(InvalidSessionStrategy.class, getInvalidSessionStrategy());
	}

	@Override
	public void configure(H http) {
		//获得HttpSession级别的安全上下文存储策略
		SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
		//创建第一个过滤器
		SessionManagementFilter sessionManagementFilter = new SessionManagementFilter(securityContextRepository,
				getSessionAuthenticationStrategy(http));

		//设置出现异常跳转的Url
		if (this.sessionAuthenticationErrorUrl != null) {
			sessionManagementFilter.setAuthenticationFailureHandler(
					new SimpleUrlAuthenticationFailureHandler(this.sessionAuthenticationErrorUrl));
		}

		//获得HttpSession过期(无效)策略
		InvalidSessionStrategy strategy = getInvalidSessionStrategy();
		if (strategy != null) {
			sessionManagementFilter.setInvalidSessionStrategy(strategy);
		}

		//获得执行HttpSession认证策略的时候出现异常的 失败策略
		AuthenticationFailureHandler failureHandler = getSessionAuthenticationFailureHandler();
		if (failureHandler != null) {
			sessionManagementFilter.setAuthenticationFailureHandler(failureHandler);
		}

		//获得认证对象解析器
		AuthenticationTrustResolver trustResolver = http.getSharedObject(AuthenticationTrustResolver.class);
		if (trustResolver != null) {
			sessionManagementFilter.setTrustResolver(trustResolver);
		}

		//每一个Filter必执行的postProcess方法
		sessionManagementFilter = postProcess(sessionManagementFilter);
		//添加到HttpSecurity的过滤器集合中
		http.addFilter(sessionManagementFilter);
		//当开启了并发会话的限制
		if (isConcurrentSessionControlEnabled()) {
			//创建第二个过滤器
			ConcurrentSessionFilter concurrentSessionFilter = createConcurrencyFilter(http);

			concurrentSessionFilter = postProcess(concurrentSessionFilter);
			http.addFilter(concurrentSessionFilter);
		}
	}

	/**
	 * 创建一个有关并发会话限制的过滤器
	 * @param http
	 * @return
	 */
	private ConcurrentSessionFilter createConcurrencyFilter(H http) {
		//获得SessionInformation过期策略
		SessionInformationExpiredStrategy expireStrategy = getExpiredSessionStrategy();
		//获得SessionInformation注册中心
		SessionRegistry sessionRegistry = getSessionRegistry(http);

		//创建过滤器
		ConcurrentSessionFilter concurrentSessionFilter = (expireStrategy != null)
				? new ConcurrentSessionFilter(sessionRegistry, expireStrategy)
				//虽然这里没传SessionInformation过期策略，但是构造方法实际上创建了默认的
				: new ConcurrentSessionFilter(sessionRegistry);

		//重点：从httpSecurity中获得登出配置类
		LogoutConfigurer<H> logoutConfigurer = http.getConfigurer(LogoutConfigurer.class);
		if (logoutConfigurer != null) {
			//拿到登出处理器
			List<LogoutHandler> logoutHandlers = logoutConfigurer.getLogoutHandlers();
			if (!CollectionUtils.isEmpty(logoutHandlers)) {
				//设置到ConcurrentSessionFilter过滤器中了，这样这个过滤器就可以做登出操作了
				concurrentSessionFilter.setLogoutHandlers(logoutHandlers);
			}
		}
		return concurrentSessionFilter;
	}

	/**
	 * 获得HttpSession过期(无效)策略
	 */
	InvalidSessionStrategy getInvalidSessionStrategy() {
		if (this.invalidSessionStrategy != null) {
			return this.invalidSessionStrategy;
		}
		if (this.invalidSessionUrl == null) {
			return null;
		}
		this.invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(this.invalidSessionUrl);
		return this.invalidSessionStrategy;
	}

	/**
	 * 获得SessionInformation过期策略
	 * @return
	 */
	SessionInformationExpiredStrategy getExpiredSessionStrategy() {
		if (this.expiredSessionStrategy != null) {
			return this.expiredSessionStrategy;
		}
		if (this.expiredUrl == null) {
			return null;
		}
		this.expiredSessionStrategy = new SimpleRedirectSessionInformationExpiredStrategy(this.expiredUrl);
		return this.expiredSessionStrategy;
	}

	/**
	 * 获得执行HttpSession认证策略的时候出现异常的 失败策略
	 * @return
	 */
	AuthenticationFailureHandler getSessionAuthenticationFailureHandler() {
		if (this.sessionAuthenticationFailureHandler != null) {
			return this.sessionAuthenticationFailureHandler;
		}
		if (this.sessionAuthenticationErrorUrl == null) {
			return null;
		}
		this.sessionAuthenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler(
				this.sessionAuthenticationErrorUrl);
		return this.sessionAuthenticationFailureHandler;
	}

	/**
	 * 获得创建session的策略
	 */
	SessionCreationPolicy getSessionCreationPolicy() {
		if (this.sessionPolicy != null) {
			return this.sessionPolicy;
		}
		//尝试从构建器的sharedObjects获取创建session策略
		SessionCreationPolicy sessionPolicy = getBuilder().getSharedObject(SessionCreationPolicy.class);
		//如果没有设置就设置为需要就创建
		return (sessionPolicy != null) ? sessionPolicy : SessionCreationPolicy.IF_REQUIRED;
	}

	/**
	 * 是否允许创建HttpSession
	 */
	private boolean isAllowSessionCreation() {
		SessionCreationPolicy sessionPolicy = getSessionCreationPolicy();
		return SessionCreationPolicy.ALWAYS == sessionPolicy || SessionCreationPolicy.IF_REQUIRED == sessionPolicy;
	}

	/**
	 * 如果完全不需要创建session就返回true
	 */
	private boolean isStateless() {
		//获得创建session的策略
		SessionCreationPolicy sessionPolicy = getSessionCreationPolicy();
		//判断是否是完全不需要
		return SessionCreationPolicy.STATELESS == sessionPolicy;
	}

	/**
	 * 获得HttpSession认证策略
	 */
	private SessionAuthenticationStrategy getSessionAuthenticationStrategy(H http) {
		//如果以前执行过本方法那么这个就不为空
		if (this.sessionAuthenticationStrategy != null) {
			return this.sessionAuthenticationStrategy;
		}
		//获得用户设置过的session认证策略
		List<SessionAuthenticationStrategy> delegateStrategies = this.sessionAuthenticationStrategies;
		SessionAuthenticationStrategy defaultSessionAuthenticationStrategy;
		//默认session策略取哪一个
		//可以看出一个会执行postProcess方法
		if (this.providedSessionAuthenticationStrategy == null) {
			defaultSessionAuthenticationStrategy = postProcess(this.sessionFixationAuthenticationStrategy);
		}
		else {
			defaultSessionAuthenticationStrategy = this.providedSessionAuthenticationStrategy;
		}

		//是否需要限制用户的并发数
		if (isConcurrentSessionControlEnabled()) {
			//获得SessionInformation注册中心
			SessionRegistry sessionRegistry = getSessionRegistry(http);
			//创建一个处理并发会话控制的策略
			ConcurrentSessionControlAuthenticationStrategy concurrentSessionControlStrategy = new ConcurrentSessionControlAuthenticationStrategy(
					sessionRegistry);
			concurrentSessionControlStrategy.setMaximumSessions(this.maximumSessions);
			concurrentSessionControlStrategy.setExceptionIfMaximumExceeded(this.maxSessionsPreventsLogin);
			concurrentSessionControlStrategy = postProcess(concurrentSessionControlStrategy);

			//创建一个注册SessionInformation的策略
			RegisterSessionAuthenticationStrategy registerSessionStrategy = new RegisterSessionAuthenticationStrategy(
					sessionRegistry);
			registerSessionStrategy = postProcess(registerSessionStrategy);

			//通常来说是添加一个防止固定会话攻击的策略
			delegateStrategies.addAll(Arrays.asList(concurrentSessionControlStrategy,
					defaultSessionAuthenticationStrategy, registerSessionStrategy));
			//也就说只要开启了限制会话并发数，那么就至少有这三个策略
		}
		else {
			//否则默认就只有防止固定会话攻击的策略
			delegateStrategies.add(defaultSessionAuthenticationStrategy);
		}
		//变成一个混合型的HttpSession认证策略，并设置到对应的位置上
		this.sessionAuthenticationStrategy = postProcess(
				new CompositeSessionAuthenticationStrategy(delegateStrategies));
		return this.sessionAuthenticationStrategy;
	}

	/**
	 * 获得SessionInformation注册中心
	 * @param http
	 * @return
	 */
	private SessionRegistry getSessionRegistry(H http) {
		//可能已经配置了注册中心
		//尝试从容器中获取
		if (this.sessionRegistry == null) {
			this.sessionRegistry = getBeanOrNull(SessionRegistry.class);
		}
		//自己创建默认的实现
		if (this.sessionRegistry == null) {
			SessionRegistryImpl sessionRegistry = new SessionRegistryImpl();
			//重点：注册监听器
			registerDelegateApplicationListener(http, sessionRegistry);
			this.sessionRegistry = sessionRegistry;
		}
		return this.sessionRegistry;
	}

	/**
	 * 注册一个监听器
	 * 这是为了当HttpSession过期了或者sessionId改变了，那么与之对应的SessionInformation也要发生改变
	 * @param http
	 * @param delegate
	 */
	private void registerDelegateApplicationListener(H http, ApplicationListener<?> delegate) {
		DelegatingApplicationListener delegating = getBeanOrNull(DelegatingApplicationListener.class);
		if (delegating == null) {
			return;
		}
		SmartApplicationListener smartListener = new GenericApplicationListenerAdapter(delegate);
		delegating.addListener(smartListener);
	}

	/**
	 * 如果需要限制每个用户的并发会话数，则返回true。
	 * @return
	 */
	private boolean isConcurrentSessionControlEnabled() {
		return this.maximumSessions != null;
	}

	/**
	 * Creates the default {@link SessionAuthenticationStrategy} for session fixation
	 * @return the default {@link SessionAuthenticationStrategy} for session fixation
	 */
	private static SessionAuthenticationStrategy createDefaultSessionFixationProtectionStrategy() {
		return new ChangeSessionIdAuthenticationStrategy();
	}

	private <T> T getBeanOrNull(Class<T> type) {
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
		if (context == null) {
			return null;
		}
		try {
			return context.getBean(type);
		}
		catch (NoSuchBeanDefinitionException ex) {
			return null;
		}
	}

	/**
	 * 防止固定会话攻击的策略 的配置类
	 * 有两种不同的方案，但归根结底都是将认证前后的Session发生变化
	 */
	public final class SessionFixationConfigurer {

		/**
		 * 开启防止固定会话攻击的策略
		 */
		public SessionManagementConfigurer<H> newSession() {
			SessionFixationProtectionStrategy sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
			sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);
			setSessionFixationAuthenticationStrategy(sessionFixationProtectionStrategy);
			return SessionManagementConfigurer.this;
		}

		/**
		 * 开启防止固定会话攻击的策略
		 * 是重新创建Session的策略
		 */
		public SessionManagementConfigurer<H> migrateSession() {
			setSessionFixationAuthenticationStrategy(new SessionFixationProtectionStrategy());
			return SessionManagementConfigurer.this;
		}

		/**
		 * 开启防止固定会话攻击的策略
		 * 是改变SessionId的策略
		 */
		public SessionManagementConfigurer<H> changeSessionId() {
			setSessionFixationAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
			return SessionManagementConfigurer.this;
		}

		/**
		 * 关闭防止固定会话攻击的策略
		 */
		public SessionManagementConfigurer<H> none() {
			setSessionFixationAuthenticationStrategy(new NullAuthenticatedSessionStrategy());
			return SessionManagementConfigurer.this;
		}

	}

	/**
	 * 并发会话的 配置类
	 */
	public final class ConcurrencyControlConfigurer {

		private ConcurrencyControlConfigurer() {
		}

		/**
		 * 控制用户的最大会话数。默认情况下允许任意数量的用户
		 * @param maximumSessions
		 * @return
		 */
		public ConcurrencyControlConfigurer maximumSessions(int maximumSessions) {
			SessionManagementConfigurer.this.maximumSessions = maximumSessions;
			return this;
		}

		/**
		 * The URL to redirect to if a user tries to access a resource and their session
		 * has been expired due to too many sessions for the current user. The default is
		 * to write a simple error message to the response.
		 * @param expiredUrl the URL to redirect to
		 * @return the {@link ConcurrencyControlConfigurer} for further customizations
		 */
		public ConcurrencyControlConfigurer expiredUrl(String expiredUrl) {
			SessionManagementConfigurer.this.expiredUrl = expiredUrl;
			return this;
		}

		/**
		 * Determines the behaviour when an expired session is detected.
		 * @param expiredSessionStrategy the {@link SessionInformationExpiredStrategy} to
		 * use when an expired session is detected.
		 * @return the {@link ConcurrencyControlConfigurer} for further customizations
		 */
		public ConcurrencyControlConfigurer expiredSessionStrategy(
				SessionInformationExpiredStrategy expiredSessionStrategy) {
			SessionManagementConfigurer.this.expiredSessionStrategy = expiredSessionStrategy;
			return this;
		}

		/**
		 * If true, prevents a user from authenticating when the
		 * {@link #maximumSessions(int)} has been reached. Otherwise (default), the user
		 * who authenticates is allowed access and an existing user's session is expired.
		 * The user's who's session is forcibly expired is sent to
		 * {@link #expiredUrl(String)}. The advantage of this approach is if a user
		 * accidentally does not log out, there is no need for an administrator to
		 * intervene or wait till their session expires.
		 * @param maxSessionsPreventsLogin true to have an error at time of
		 * authentication, else false (default)
		 * @return the {@link ConcurrencyControlConfigurer} for further customizations
		 */
		public ConcurrencyControlConfigurer maxSessionsPreventsLogin(boolean maxSessionsPreventsLogin) {
			SessionManagementConfigurer.this.maxSessionsPreventsLogin = maxSessionsPreventsLogin;
			return this;
		}

		/**
		 * Controls the {@link SessionRegistry} implementation used. The default is
		 * {@link SessionRegistryImpl} which is an in memory implementation.
		 * @param sessionRegistry the {@link SessionRegistry} to use
		 * @return the {@link ConcurrencyControlConfigurer} for further customizations
		 */
		public ConcurrencyControlConfigurer sessionRegistry(SessionRegistry sessionRegistry) {
			SessionManagementConfigurer.this.sessionRegistry = sessionRegistry;
			return this;
		}

		/**
		 * Used to chain back to the {@link SessionManagementConfigurer}
		 * @return the {@link SessionManagementConfigurer} for further customizations
		 */
		public SessionManagementConfigurer<H> and() {
			return SessionManagementConfigurer.this;
		}

	}

}

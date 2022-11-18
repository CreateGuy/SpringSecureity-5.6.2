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

import java.util.Arrays;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.openid.OpenIDLoginConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * 认证过滤器的基类，比如说实现类有 FormLoginConfigurer
 */
public abstract class AbstractAuthenticationFilterConfigurer<B extends HttpSecurityBuilder<B>, T extends AbstractAuthenticationFilterConfigurer<B, T, F>, F extends AbstractAuthenticationProcessingFilter>
		extends AbstractHttpConfigurer<T, B> {

	/**
	 * 认证过滤器
	 */
	private F authFilter;

	/**
	 * 认证信息详情源
	 */
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	/**
	 * 默认认证成功处理器，是一个关于RequestCache的
	 */
	private SavedRequestAwareAuthenticationSuccessHandler defaultSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();

	private AuthenticationSuccessHandler successHandler = this.defaultSuccessHandler;

	/**
	 * 身份验证入口点
	 * <ul>
	 *     <li>
	 *         通常是转发到登录页
	 *     </li>
	 *     <li>
	 *         一般是都是在FilterSecurityInterceptor出现认证失败的时候，被ExceptionTranslationFilter捕获到时候调用
	 *     </li>
	 * </ul>
	 */
	private LoginUrlAuthenticationEntryPoint authenticationEntryPoint;

	/**
	 * 用户是否自定义了登录页
	 */
	private boolean customLoginPage;

	/**
	 * 登录页
	 */
	private String loginPage;

	/**
	 * 认证(登录)请求的地址
	 */
	private String loginProcessingUrl;

	/**
	 * 认证失败处理器
	 */
	private AuthenticationFailureHandler failureHandler;

	/**
	 * 是否放行登录请求
	 * <ul>
	 *     <li>
	 *         实际上不设置这个属性为Ture也行, 因为登录页过滤器和表单登录过滤器都在权限验证过滤器(FilterSecurityInterceptor)前面,在这之前就已经做了处理了
	 *     </li>
	 * </ul>
	 */
	private boolean permitAll;

	/**
	 * 认证失败跳转的Url
	 */
	private String failureUrl;

	/**
	 * Creates a new instance with minimal defaults
	 */
	protected AbstractAuthenticationFilterConfigurer() {
		setLoginPage("/login");
	}

	/**
	 * Creates a new instance
	 * @param authenticationFilter the {@link AbstractAuthenticationProcessingFilter} to
	 * use
	 * @param defaultLoginProcessingUrl the default URL to use for
	 * {@link #loginProcessingUrl(String)}
	 */
	protected AbstractAuthenticationFilterConfigurer(F authenticationFilter, String defaultLoginProcessingUrl) {
		this();
		this.authFilter = authenticationFilter;
		if (defaultLoginProcessingUrl != null) {
			loginProcessingUrl(defaultLoginProcessingUrl);
		}
	}

	/**
	 * Specifies where users will be redirected after authenticating successfully if they
	 * have not visited a secured page prior to authenticating. This is a shortcut for
	 * calling {@link #defaultSuccessUrl(String, boolean)}.
	 * @param defaultSuccessUrl the default success url
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T defaultSuccessUrl(String defaultSuccessUrl) {
		return defaultSuccessUrl(defaultSuccessUrl, false);
	}

	/**
	 * 指定在身份认证成功后，如果用户在身份认证之前没有访问过页面，将被重定向到某个地方
	 * @param defaultSuccessUrl
	 * @param alwaysUse
	 * @return
	 */
	public final T defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
		SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
		handler.setDefaultTargetUrl(defaultSuccessUrl);
		handler.setAlwaysUseDefaultTargetUrl(alwaysUse);
		this.defaultSuccessHandler = handler;
		return successHandler(handler);
	}

	/**
	 * 设置认证请求的Url
	 */
	public T loginProcessingUrl(String loginProcessingUrl) {
		this.loginProcessingUrl = loginProcessingUrl;
		this.authFilter.setRequiresAuthenticationRequestMatcher(createLoginProcessingUrlMatcher(loginProcessingUrl));
		return getSelf();
	}

	/**
	 * Create the {@link RequestMatcher} given a loginProcessingUrl
	 * @param loginProcessingUrl creates the {@link RequestMatcher} based upon the
	 * loginProcessingUrl
	 * @return the {@link RequestMatcher} to use based upon the loginProcessingUrl
	 */
	protected abstract RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl);

	/**
	 * Specifies a custom {@link AuthenticationDetailsSource}. The default is
	 * {@link WebAuthenticationDetailsSource}.
	 * @param authenticationDetailsSource the custom {@link AuthenticationDetailsSource}
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T authenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
		return getSelf();
	}

	/**
	 * Specifies the {@link AuthenticationSuccessHandler} to be used. The default is
	 * {@link SavedRequestAwareAuthenticationSuccessHandler} with no additional properties
	 * set.
	 * @param successHandler the {@link AuthenticationSuccessHandler}.
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T successHandler(AuthenticationSuccessHandler successHandler) {
		this.successHandler = successHandler;
		return getSelf();
	}

	/**
	 * Equivalent of invoking permitAll(true)
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T permitAll() {
		return permitAll(true);
	}

	/**
	 * Ensures the urls for {@link #failureUrl(String)} as well as for the
	 * {@link HttpSecurityBuilder}, the {@link #getLoginPage} and
	 * {@link #getLoginProcessingUrl} are granted access to any user.
	 * @param permitAll true to grant access to the URLs false to skip this step
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T permitAll(boolean permitAll) {
		this.permitAll = permitAll;
		return getSelf();
	}

	/**
	 * The URL to send users if authentication fails. This is a shortcut for invoking
	 * {@link #failureHandler(AuthenticationFailureHandler)}. The default is
	 * "/login?error".
	 * @param authenticationFailureUrl the URL to send users if authentication fails (i.e.
	 * "/login?error").
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T failureUrl(String authenticationFailureUrl) {
		T result = failureHandler(new SimpleUrlAuthenticationFailureHandler(authenticationFailureUrl));
		this.failureUrl = authenticationFailureUrl;
		return result;
	}

	/**
	 * Specifies the {@link AuthenticationFailureHandler} to use when authentication
	 * fails. The default is redirecting to "/login?error" using
	 * {@link SimpleUrlAuthenticationFailureHandler}
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} to use
	 * when authentication fails.
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T failureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		this.failureUrl = null;
		this.failureHandler = authenticationFailureHandler;
		return getSelf();
	}

	@Override
	public void init(B http) throws Exception {
		//更新一些默认值
		updateAuthenticationDefaults();
		//更新可直接访问的Url
		updateAccessDefaults(http);
		//注册一个身份认证入口点
		registerDefaultAuthenticationEntryPoint(http);
	}

	/**
	 * 注册一个身份认证入口点
	 * @param http
	 */
	@SuppressWarnings("unchecked")
	protected final void registerDefaultAuthenticationEntryPoint(B http) {
		registerAuthenticationEntryPoint(http, this.authenticationEntryPoint);
	}

	/**
	 * 注册一个身份认证入口点
	 * @param http
	 * @param authenticationEntryPoint
	 */
	@SuppressWarnings("unchecked")
	protected final void registerAuthenticationEntryPoint(B http, AuthenticationEntryPoint authenticationEntryPoint) {
		ExceptionHandlingConfigurer<B> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling == null) {
			return;
		}
		//将身份认证入口点和对应的请求匹配器 放入异常处理配置类中
		exceptionHandling.defaultAuthenticationEntryPointFor(postProcess(authenticationEntryPoint),
				getAuthenticationEntryPointMatcher(http));
	}

	/**
	 * 返回一个身份认证入口点的请求匹配器
	 * @param http
	 * @return
	 */
	protected final RequestMatcher getAuthenticationEntryPointMatcher(B http) {
		ContentNegotiationStrategy contentNegotiationStrategy = http.getSharedObject(ContentNegotiationStrategy.class);
		if (contentNegotiationStrategy == null) {
			contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
		}
		//第一个请求匹配器要求：媒体类型必须是下面这几种
		MediaTypeRequestMatcher mediaMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy,
				MediaType.APPLICATION_XHTML_XML, new MediaType("image", "*"), MediaType.TEXT_HTML,
				MediaType.TEXT_PLAIN);
		mediaMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		//第二个请求匹配器要求 X-Requested-With 值不能是 XMLHttpRequest
		RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
				new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));
		//是一个And的
		return new AndRequestMatcher(Arrays.asList(notXRequestedWith, mediaMatcher));
	}

	@Override
	public void configure(B http) throws Exception {
		//设置端口映射器
		PortMapper portMapper = http.getSharedObject(PortMapper.class);
		if (portMapper != null) {
			this.authenticationEntryPoint.setPortMapper(portMapper);
		}
		//设置请求缓存器
		RequestCache requestCache = http.getSharedObject(RequestCache.class);
		if (requestCache != null) {
			this.defaultSuccessHandler.setRequestCache(requestCache);
		}

		//设置局部认证管理器，认证成功处理器，认证失败处理器
		this.authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
		this.authFilter.setAuthenticationSuccessHandler(this.successHandler);
		this.authFilter.setAuthenticationFailureHandler(this.failureHandler);

		if (this.authenticationDetailsSource != null) {
			this.authFilter.setAuthenticationDetailsSource(this.authenticationDetailsSource);
		}

		//当开启了会话管理的功能的时候，拿到Session认证策略
		SessionAuthenticationStrategy sessionAuthenticationStrategy = http
				.getSharedObject(SessionAuthenticationStrategy.class);
		if (sessionAuthenticationStrategy != null) {
			this.authFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
		}

		//当开启了记住我的功能的时候，拿到记住我服务
		RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
		if (rememberMeServices != null) {
			this.authFilter.setRememberMeServices(rememberMeServices);
		}
		F filter = postProcess(this.authFilter);
		http.addFilter(filter);
	}

	/**
	 * <p>
	 * Specifies the URL to send users to if login is required. If used with
	 * {@link WebSecurityConfigurerAdapter} a default login page will be generated when
	 * this attribute is not specified.
	 * </p>
	 *
	 * <p>
	 * If a URL is specified or this is not being used in conjunction with
	 * {@link WebSecurityConfigurerAdapter}, users are required to process the specified
	 * URL to generate a login page.
	 * </p>
	 */
	protected T loginPage(String loginPage) {
		setLoginPage(loginPage);
		updateAuthenticationDefaults();
		this.customLoginPage = true;
		return getSelf();
	}

	/**
	 * @return true if a custom login page has been specified, else false
	 */
	public final boolean isCustomLoginPage() {
		return this.customLoginPage;
	}

	/**
	 * Gets the Authentication Filter
	 * @return the Authentication Filter
	 */
	protected final F getAuthenticationFilter() {
		return this.authFilter;
	}

	/**
	 * Sets the Authentication Filter
	 * @param authFilter the Authentication Filter
	 */
	protected final void setAuthenticationFilter(F authFilter) {
		this.authFilter = authFilter;
	}

	/**
	 * Gets the login page
	 * @return the login page
	 */
	protected final String getLoginPage() {
		return this.loginPage;
	}

	/**
	 * Gets the Authentication Entry Point
	 * @return the Authentication Entry Point
	 */
	protected final AuthenticationEntryPoint getAuthenticationEntryPoint() {
		return this.authenticationEntryPoint;
	}

	/**
	 * Gets the URL to submit an authentication request to (i.e. where username/password
	 * must be submitted)
	 * @return the URL to submit an authentication request to
	 */
	protected final String getLoginProcessingUrl() {
		return this.loginProcessingUrl;
	}

	/**
	 * Gets the URL to send users to if authentication fails
	 * @return the URL to send users if authentication fails (e.g. "/login?error").
	 */
	protected final String getFailureUrl() {
		return this.failureUrl;
	}

	/**
	 * 更新一些默认值
	 * @throws Exception
	 */
	protected final void updateAuthenticationDefaults() {
		//当没有配认证请求的Url的时候，将登录页的URL + POST请求方式当做 认证请求
		if (this.loginProcessingUrl == null) {
			loginProcessingUrl(this.loginPage);
		}
		//当没有配认证失败处理器的时候，将登录页 + ?error当做 失败跳转的地址
		if (this.failureHandler == null) {
			failureUrl(this.loginPage + "?error");
		}

		//当开启了登出功能的时候，但是没有设置登出成功跳转的Url的时候，使用 登录页 + ?logout
		LogoutConfigurer<B> logoutConfigurer = getBuilder().getConfigurer(LogoutConfigurer.class);
		if (logoutConfigurer != null && !logoutConfigurer.isCustomLogoutSuccess()) {
			logoutConfigurer.logoutSuccessUrl(this.loginPage + "?logout");
		}
	}

	/**
	 * 更新可直接访问的Url
	 */
	protected final void updateAccessDefaults(B http) {
		//放行登录页，认证(登录)请求，认证失败跳转的Url
		if (this.permitAll) {
			PermitAllSupport.permitAll(http, this.loginPage, this.loginProcessingUrl, this.failureUrl);
		}
	}

	/**
	 * Sets the loginPage and updates the {@link AuthenticationEntryPoint}.
	 * @param loginPage
	 */
	private void setLoginPage(String loginPage) {
		this.loginPage = loginPage;
		this.authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(loginPage);
	}

	@SuppressWarnings("unchecked")
	private T getSelf() {
		return (T) this;
	}

}

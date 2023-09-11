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
import java.util.LinkedHashMap;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.DelegatingLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * 登出过滤器配置类
 */
public final class LogoutConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<LogoutConfigurer<H>, H> {

	/**
	 * 登出处理器
	 */
	private List<LogoutHandler> logoutHandlers = new ArrayList<>();

	/**
	 * 清空线程级别上下文的登出处理器
	 * 也是默认添加的登出处理器
	 */
	private SecurityContextLogoutHandler contextLogoutHandler = new SecurityContextLogoutHandler();

	/**
	 * 登出成功跳转的Url，优先使用下面的处理器
	 */
	private String logoutSuccessUrl = "/login?logout";

	/**
	 * 登出成功跳转的处理器
	 */
	private LogoutSuccessHandler logoutSuccessHandler;

	/**
	 * 登出的Url
	 */
	private String logoutUrl = "/logout";

	/**
	 * 判断是否是登出请求的请求匹配器
	 */
	private RequestMatcher logoutRequestMatcher;

	/**
	 * 是否放行登出成功跳转的Url
	 */
	private boolean permitAll;

	/**
	 * 是否用户自定义了登出成功跳转的Url/处理器
	 */
	private boolean customLogoutSuccess;

	/**
	 * 根据请求匹配器执行不同的登出成功处理器
	 * 使用场景1：默认是GET,POST,PUT,DELETE的/logout作为登出Url，那么就可以执行不同的登出成功处理器
	 * 使用场景2：直接修改请求匹配器，设定多个Url都可以进行登出操作，那么也以执行不同的登出成功处理器
	 */
	private LinkedHashMap<RequestMatcher, LogoutSuccessHandler> defaultLogoutSuccessHandlerMappings = new LinkedHashMap<>();

	/**
	 * Creates a new instance
	 * @see HttpSecurity#logout()
	 */
	public LogoutConfigurer() {
	}

	/**
	 * Adds a {@link LogoutHandler}. {@link SecurityContextLogoutHandler} and
	 * {@link LogoutSuccessEventPublishingLogoutHandler} are added as last
	 * {@link LogoutHandler} instances by default.
	 * @param logoutHandler the {@link LogoutHandler} to add
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> addLogoutHandler(LogoutHandler logoutHandler) {
		Assert.notNull(logoutHandler, "logoutHandler cannot be null");
		this.logoutHandlers.add(logoutHandler);
		return this;
	}

	/**
	 * 指定SecurityContextLogoutHandler是否应该在登出时清除认证对象
	 */
	public LogoutConfigurer<H> clearAuthentication(boolean clearAuthentication) {
		this.contextLogoutHandler.setClearAuthentication(clearAuthentication);
		return this;
	}

	/**
	 * 指定SecurityContextLogoutHandler是否应该在登出时使Session无效
	 * @param invalidateHttpSession true if the {@link HttpSession} should be invalidated
	 * (default), or false otherwise.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> invalidateHttpSession(boolean invalidateHttpSession) {
		this.contextLogoutHandler.setInvalidateHttpSession(invalidateHttpSession);
		return this;
	}

	/**
	 * 设置登出的Url
	 * <p>注意：和登出请求匹配器排斥</p>
	 * @param logoutUrl
	 * @return
	 */
	public LogoutConfigurer<H> logoutUrl(String logoutUrl) {
		this.logoutRequestMatcher = null;
		this.logoutUrl = logoutUrl;
		return this;
	}

	/**
	 * The RequestMatcher that triggers log out to occur. In most circumstances users will
	 * use {@link #logoutUrl(String)} which helps enforce good practices.
	 * @param logoutRequestMatcher the RequestMatcher used to determine if logout should
	 * occur.
	 * @return the {@link LogoutConfigurer} for further customization
	 * @see #logoutUrl(String)
	 */
	public LogoutConfigurer<H> logoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		this.logoutRequestMatcher = logoutRequestMatcher;
		return this;
	}

	/**
	 * 设置登出成功Url
	 * @param logoutSuccessUrl
	 * @return
	 */
	public LogoutConfigurer<H> logoutSuccessUrl(String logoutSuccessUrl) {
		//标记用户修改过登出成功Url或者登出的成功处理器了
		this.customLogoutSuccess = true;
		this.logoutSuccessUrl = logoutSuccessUrl;
		return this;
	}

	/**
	 * 是否放行登出成功跳转的Url
	 */
	public LogoutConfigurer<H> permitAll() {
		return permitAll(true);
	}

	/**
	 * 设定登出时要删除的cookie的名称。
	 */
	public LogoutConfigurer<H> deleteCookies(String... cookieNamesToClear) {
		return addLogoutHandler(new CookieClearingLogoutHandler(cookieNamesToClear));
	}

	/**
	 * Sets the {@link LogoutSuccessHandler} to use. If this is specified,
	 * {@link #logoutSuccessUrl(String)} is ignored.
	 * @param logoutSuccessHandler the {@link LogoutSuccessHandler} to use after a user
	 * has been logged out.
	 * @return the {@link LogoutConfigurer} for further customizations
	 */
	public LogoutConfigurer<H> logoutSuccessHandler(LogoutSuccessHandler logoutSuccessHandler) {
		this.logoutSuccessUrl = null;
		this.customLogoutSuccess = true;
		this.logoutSuccessHandler = logoutSuccessHandler;
		return this;
	}

	/**
	 * Sets a default {@link LogoutSuccessHandler} to be used which prefers being invoked
	 * for the provided {@link RequestMatcher}. If no {@link LogoutSuccessHandler} is
	 * specified a {@link SimpleUrlLogoutSuccessHandler} will be used. If any default
	 * {@link LogoutSuccessHandler} instances are configured, then a
	 * {@link DelegatingLogoutSuccessHandler} will be used that defaults to a
	 * {@link SimpleUrlLogoutSuccessHandler}.
	 * @param handler the {@link LogoutSuccessHandler} to use
	 * @param preferredMatcher the {@link RequestMatcher} for this default
	 * {@link LogoutSuccessHandler}
	 * @return the {@link LogoutConfigurer} for further customizations
	 */
	public LogoutConfigurer<H> defaultLogoutSuccessHandlerFor(LogoutSuccessHandler handler,
			RequestMatcher preferredMatcher) {
		Assert.notNull(handler, "handler cannot be null");
		Assert.notNull(preferredMatcher, "preferredMatcher cannot be null");
		this.defaultLogoutSuccessHandlerMappings.put(preferredMatcher, handler);
		return this;
	}

	/**
	 * Grants access to the {@link #logoutSuccessUrl(String)} and the
	 * {@link #logoutUrl(String)} for every user.
	 * @param permitAll if true grants access, else nothing is done
	 * @return the {@link LogoutConfigurer} for further customization.
	 */
	public LogoutConfigurer<H> permitAll(boolean permitAll) {
		this.permitAll = permitAll;
		return this;
	}

	/**
	 * 获得登出成功处理器，可能会通过登出成功Url构建
	 */
	public LogoutSuccessHandler getLogoutSuccessHandler() {
		LogoutSuccessHandler handler = this.logoutSuccessHandler;
		if (handler == null) {
			//创建默认的登出成功处理器
			handler = createDefaultSuccessHandler();
			this.logoutSuccessHandler = handler;
		}
		return handler;
	}

	/**
	 * 创建默认的登出成功处理器
	 * @return
	 */
	private LogoutSuccessHandler createDefaultSuccessHandler() {
		SimpleUrlLogoutSuccessHandler urlLogoutHandler = new SimpleUrlLogoutSuccessHandler();
		urlLogoutHandler.setDefaultTargetUrl(this.logoutSuccessUrl);
		if (this.defaultLogoutSuccessHandlerMappings.isEmpty()) {
			return urlLogoutHandler;
		}
		DelegatingLogoutSuccessHandler successHandler = new DelegatingLogoutSuccessHandler(
				this.defaultLogoutSuccessHandlerMappings);
		successHandler.setDefaultLogoutSuccessHandler(urlLogoutHandler);
		return successHandler;
	}

	@Override
	public void init(H http) {
		//如果允许放行
		if (this.permitAll) {
			//两个都是放行登出成功Url
			PermitAllSupport.permitAll(http, this.logoutSuccessUrl);
			PermitAllSupport.permitAll(http, this.getLogoutRequestMatcher(http));
		}

		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		//当有登录页配置类的时候并且用户没有自定义了登出成功跳转的Url/处理器
		if (loginPageGeneratingFilter != null && !isCustomLogoutSuccess()) {
			//设置登录页的登出成功Url
			loginPageGeneratingFilter.setLogoutSuccessUrl(getLogoutSuccessUrl());
		}
	}

	@Override
	public void configure(H http) throws Exception {
		LogoutFilter logoutFilter = createLogoutFilter(http);
		http.addFilter(logoutFilter);
	}

	/**
	 * Returns true if the logout success has been customized via
	 * {@link #logoutSuccessUrl(String)} or
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)}.
	 * @return true if logout success handling has been customized, else false
	 */
	boolean isCustomLogoutSuccess() {
		return this.customLogoutSuccess;
	}

	/**
	 * Gets the logoutSuccesUrl or null if a
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)} was configured.
	 * @return the logoutSuccessUrl
	 */
	private String getLogoutSuccessUrl() {
		return this.logoutSuccessUrl;
	}

	/**
	 * Gets the {@link LogoutHandler} instances that will be used.
	 * @return the {@link LogoutHandler} instances. Cannot be null.
	 */
	public List<LogoutHandler> getLogoutHandlers() {
		return this.logoutHandlers;
	}

	/**
	 * 创建登出过滤器
	 */
	private LogoutFilter createLogoutFilter(H http) {
		//添加登出处理器
		this.logoutHandlers.add(this.contextLogoutHandler);
		//这里多执行了postProcess()方法，是因为这个登出处理器需要一个ApplicationEventPublisher
		this.logoutHandlers.add(postProcess(new LogoutSuccessEventPublishingLogoutHandler()));

		//所有的登出处理器
		LogoutHandler[] handlers = this.logoutHandlers.toArray(new LogoutHandler[0]);
		//创建过滤器
		LogoutFilter result = new LogoutFilter(
				//获得登出成功处理器
				getLogoutSuccessHandler()
				, handlers);
		//设置登出请求的匹配器
		result.setLogoutRequestMatcher(getLogoutRequestMatcher(http));
		result = postProcess(result);
		return result;
	}

	/**
	 * 获得登出请求的匹配器
	 * @param http
	 * @return
	 */
	private RequestMatcher getLogoutRequestMatcher(H http) {
		if (this.logoutRequestMatcher != null) {
			return this.logoutRequestMatcher;
		}
		this.logoutRequestMatcher = createLogoutRequestMatcher(http);
		return this.logoutRequestMatcher;
	}

	/**
	 * 创建默认的登出请求的匹配器
	 * <P>
	 *     是根据登出Url+四种请求方式创建出来的
	 * </P>
	 * @param http
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private RequestMatcher createLogoutRequestMatcher(H http) {
		RequestMatcher post = createLogoutRequestMatcher("POST");
		if (http.getConfigurer(CsrfConfigurer.class) != null) {
			return post;
		}
		RequestMatcher get = createLogoutRequestMatcher("GET");
		RequestMatcher put = createLogoutRequestMatcher("PUT");
		RequestMatcher delete = createLogoutRequestMatcher("DELETE");
		return new OrRequestMatcher(get, post, put, delete);
	}

	private RequestMatcher createLogoutRequestMatcher(String httpMethod) {
		return new AntPathRequestMatcher(this.logoutUrl, httpMethod);
	}

}

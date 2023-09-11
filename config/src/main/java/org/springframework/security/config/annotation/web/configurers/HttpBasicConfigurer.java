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
import java.util.LinkedHashMap;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * 基本认证过滤器的配置类
 */
public final class HttpBasicConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<HttpBasicConfigurer<B>, B> {

	/**
	 * 本配置类提供的身份认证入口点 对应的 请求匹配器
	 * <p>要求是X-Requested-With 必须是 XMLHttpRequest(异步请求)</p>
	 */
	private static final RequestHeaderRequestMatcher X_REQUESTED_WITH = new RequestHeaderRequestMatcher(
			"X-Requested-With", "XMLHttpRequest");

	/**
	 * 用来指示需要哪个域的用户名和密码
	 */
	private static final String DEFAULT_REALM = "Realm";

	/**
	 * 最终 提供给ExceptionTranslationFilter的身份认证入口点
	 */
	private AuthenticationEntryPoint authenticationEntryPoint;

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	/**
	 * 默认 提供给ExceptionTranslationFilter的身份认证入口点
	 */
	private BasicAuthenticationEntryPoint basicAuthEntryPoint = new BasicAuthenticationEntryPoint();

	/**
	 * Creates a new instance
	 * @see HttpSecurity#httpBasic()
	 */
	public HttpBasicConfigurer() {
		realmName(DEFAULT_REALM);
		LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
		entryPoints.put(X_REQUESTED_WITH, new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
		DelegatingAuthenticationEntryPoint defaultEntryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
		//是设置默认的身份认证入口点
		defaultEntryPoint.setDefaultEntryPoint(this.basicAuthEntryPoint);
		this.authenticationEntryPoint = defaultEntryPoint;
	}

	/**
	 * Allows easily changing the realm, but leaving the remaining defaults in place. If
	 * {@link #authenticationEntryPoint(AuthenticationEntryPoint)} has been invoked,
	 * invoking this method will result in an error.
	 * @param realmName the HTTP Basic realm to use
	 * @return {@link HttpBasicConfigurer} for additional customization
	 */
	public HttpBasicConfigurer<B> realmName(String realmName) {
		this.basicAuthEntryPoint.setRealmName(realmName);
		this.basicAuthEntryPoint.afterPropertiesSet();
		return this;
	}

	/**
	 * The {@link AuthenticationEntryPoint} to be populated on
	 * {@link BasicAuthenticationFilter} in the event that authentication fails. The
	 * default to use {@link BasicAuthenticationEntryPoint} with the realm "Realm".
	 * @param authenticationEntryPoint the {@link AuthenticationEntryPoint} to use
	 * @return {@link HttpBasicConfigurer} for additional customization
	 */
	public HttpBasicConfigurer<B> authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		return this;
	}

	/**
	 * Specifies a custom {@link AuthenticationDetailsSource} to use for basic
	 * authentication. The default is {@link WebAuthenticationDetailsSource}.
	 * @param authenticationDetailsSource the custom {@link AuthenticationDetailsSource}
	 * to use
	 * @return {@link HttpBasicConfigurer} for additional customization
	 */
	public HttpBasicConfigurer<B> authenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
		return this;
	}

	@Override
	public void init(B http) {
		registerDefaults(http);
	}

	/**
	 * 注册默认值
	 * @param http
	 */
	private void registerDefaults(B http) {
		ContentNegotiationStrategy contentNegotiationStrategy = http.getSharedObject(ContentNegotiationStrategy.class);
		if (contentNegotiationStrategy == null) {
			contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
		}
		MediaTypeRequestMatcher restMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy,
				MediaType.APPLICATION_ATOM_XML, MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
				MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML, MediaType.MULTIPART_FORM_DATA,
				MediaType.TEXT_XML);
		restMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		//第一个请求匹配器
		MediaTypeRequestMatcher allMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy, MediaType.ALL);
		allMatcher.setUseEquals(true);


		RequestMatcher notHtmlMatcher = new NegatedRequestMatcher(
				new MediaTypeRequestMatcher(contentNegotiationStrategy, MediaType.TEXT_HTML));

		//第二个请求匹配器
		RequestMatcher restNotHtmlMatcher = new AndRequestMatcher(
				Arrays.<RequestMatcher>asList(notHtmlMatcher, restMatcher));

		RequestMatcher preferredMatcher = new OrRequestMatcher(
				Arrays.asList(X_REQUESTED_WITH, restNotHtmlMatcher, allMatcher));

		//注册到ExceptionTranslationFilter中
		registerDefaultEntryPoint(http, preferredMatcher);
		//注册到LogoutFilter中去
		registerDefaultLogoutSuccessHandler(http, preferredMatcher);
	}

	/**
	 * 注册到ExceptionTranslationFilter中
	 * @param http
	 * @param preferredMatcher
	 */
	private void registerDefaultEntryPoint(B http, RequestMatcher preferredMatcher) {
		ExceptionHandlingConfigurer<B> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling == null) {
			return;
		}
		exceptionHandling.defaultAuthenticationEntryPointFor(postProcess(this.authenticationEntryPoint),
				preferredMatcher);
	}

	/**
	 * 注册到LogoutFilter中去
	 * @param http
	 * @param preferredMatcher
	 */
	private void registerDefaultLogoutSuccessHandler(B http, RequestMatcher preferredMatcher) {
		LogoutConfigurer<B> logout = http.getConfigurer(LogoutConfigurer.class);
		if (logout == null) {
			return;
		}
		LogoutConfigurer<B> handler = logout.defaultLogoutSuccessHandlerFor(
				postProcess(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT)), preferredMatcher);
	}

	@Override
	public void configure(B http) {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		//创建过滤器，并设置局部认证管理器
		BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter(authenticationManager,
				this.authenticationEntryPoint);
		if (this.authenticationDetailsSource != null) {
			basicAuthenticationFilter.setAuthenticationDetailsSource(this.authenticationDetailsSource);
		}

		//设置记住我服务
		RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
		if (rememberMeServices != null) {
			basicAuthenticationFilter.setRememberMeServices(rememberMeServices);
		}


		basicAuthenticationFilter = postProcess(basicAuthenticationFilter);
		http.addFilter(basicAuthenticationFilter);
	}

}

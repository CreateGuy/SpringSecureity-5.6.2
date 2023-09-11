/*
 * Copyright 2002-2013 the original author or authors.
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
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * 请求缓存器
 * <li>
 *     使用场景1：当访问一个url出现认证异常或者访问被拒绝(匿名用户)的情况会保存这一次的请求信息，然后重定向到登录页，然后认证成功后，就会通过RequestCache重定向到第一次的请求
 * </li>
 */
public final class RequestCacheConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<RequestCacheConfigurer<H>, H> {

	public RequestCacheConfigurer() {
	}

	/**
	 * Allows explicit configuration of the {@link RequestCache} to be used. Defaults to
	 * try finding a {@link RequestCache} as a shared object. Then falls back to a
	 * {@link HttpSessionRequestCache}.
	 * @param requestCache the explicit {@link RequestCache} to use
	 * @return the {@link RequestCacheConfigurer} for further customization
	 */
	public RequestCacheConfigurer<H> requestCache(RequestCache requestCache) {
		getBuilder().setSharedObject(RequestCache.class, requestCache);
		return this;
	}

	/**
	 * 关闭此配置类
	 * 原理是去除HttpSecurity中这个配置类
	 * @return
	 */
	@Override
	public H disable() {
		getBuilder().setSharedObject(RequestCache.class, new NullRequestCache());
		return super.disable();
	}

	@Override
	public void init(H http) {
		http.setSharedObject(RequestCache.class, getRequestCache(http));
	}

	@Override
	public void configure(H http) {
		//获得请求缓存器
		RequestCache requestCache = getRequestCache(http);
		//创建对应过滤器
		RequestCacheAwareFilter requestCacheFilter = new RequestCacheAwareFilter(requestCache);
		requestCacheFilter = postProcess(requestCacheFilter);
		http.addFilter(requestCacheFilter);
	}

	/**
	 * 获得请求缓存器
	 */
	private RequestCache getRequestCache(H http) {
		//先尝试从sharedObjects中获取
		RequestCache result = http.getSharedObject(RequestCache.class);
		if (result != null) {
			return result;
		}
		//尝试从容器中获取
		result = getBeanOrNull(RequestCache.class);
		if (result != null) {
			return result;
		}
		//还是没有，就创建一个基于HttpSession的请求缓冲器
		HttpSessionRequestCache defaultCache = new HttpSessionRequestCache();
		defaultCache.setRequestMatcher(createDefaultSavedRequestMatcher(http));
		return defaultCache;
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
	 * 创建默认请求匹配器(and类型)
	 * @param http
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private RequestMatcher createDefaultSavedRequestMatcher(H http) {
		//第一个：不缓存路径为/**/favicon.*的请求
		RequestMatcher notFavIcon = new NegatedRequestMatcher(new AntPathRequestMatcher("/**/favicon.*"));
		//第二个：不缓存异步请求
		RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
				new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));
		boolean isCsrfEnabled = http.getConfigurer(CsrfConfigurer.class) != null;
		List<RequestMatcher> matchers = new ArrayList<>();
		//如果开启了Csrf的保护
		if (isCsrfEnabled) {
			//第三个：为了安全考虑，只能缓存GET方式的请求
			RequestMatcher getRequests = new AntPathRequestMatcher("/**", "GET");
			matchers.add(0, getRequests);
		}
		matchers.add(notFavIcon);
		//第四个：不缓存媒体类型为 application/json 的请求
		matchers.add(notMatchingMediaType(http, MediaType.APPLICATION_JSON));
		matchers.add(notXRequestedWith);
		//第四个：不缓存媒体类型为 multipart/form-data 的请求
		matchers.add(notMatchingMediaType(http, MediaType.MULTIPART_FORM_DATA));
		//第四个：不缓存媒体类型为 text/event-stream 的请求
		matchers.add(notMatchingMediaType(http, MediaType.TEXT_EVENT_STREAM));
		return new AndRequestMatcher(matchers);
	}

	/**
	 * 根据传入的媒体类型，创建一个取反的请求匹配器
	 * @param http
	 * @param mediaType
	 * @return
	 */
	private RequestMatcher notMatchingMediaType(H http, MediaType mediaType) {
		//获得内容协商策略
		//是为了解析媒体类型
		ContentNegotiationStrategy contentNegotiationStrategy = http.getSharedObject(ContentNegotiationStrategy.class);
		if (contentNegotiationStrategy == null) {
			contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
		}
		MediaTypeRequestMatcher mediaRequest = new MediaTypeRequestMatcher(contentNegotiationStrategy, mediaType);
		mediaRequest.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		return new NegatedRequestMatcher(mediaRequest);
	}

}

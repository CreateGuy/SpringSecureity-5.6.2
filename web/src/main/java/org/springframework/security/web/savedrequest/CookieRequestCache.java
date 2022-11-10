/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.web.savedrequest;

import java.util.Base64;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.WebUtils;

/**
 * 请求缓存器的一个实现，是将请求保存到Cookie中
 */
public class CookieRequestCache implements RequestCache {

	/**
	 * 请求缓存器
	 */
	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;

	protected final Log logger = LogFactory.getLog(this.getClass());

	/**
	 * 请求缓存放在Cookie中的key
	 */
	private static final String COOKIE_NAME = "REDIRECT_URI";

	/**
	 * Cookie过期时间
	 */
	private static final int COOKIE_MAX_AGE = -1;

	@Override
	public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
		if (!this.requestMatcher.matches(request)) {
			this.logger.debug("Request not saved as configured RequestMatcher did not match");
			return;
		}
		//构建重定向之前的URL
		String redirectUrl = UrlUtils.buildFullRequestUrl(request);
		//可以看出保存的是一个Base64
		Cookie savedCookie = new Cookie(COOKIE_NAME, encodeCookie(redirectUrl));
		savedCookie.setMaxAge(COOKIE_MAX_AGE);
		savedCookie.setSecure(request.isSecure());
		savedCookie.setPath(getCookiePath(request));
		//设置客户端不能访问当前Cookie
		savedCookie.setHttpOnly(true);
		response.addCookie(savedCookie);
	}

	@Override
	public SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
		//获得保存的指定Cookie
		Cookie savedRequestCookie = WebUtils.getCookie(request, COOKIE_NAME);
		if (savedRequestCookie == null) {
			return null;
		}
		//获得重定向前的原URL
		String originalURI = decodeCookie(savedRequestCookie.getValue());
		//注意：Cookie是没办法像HttpSession一样保存其他Cookie，local，header等等参数
		//因为Cookie只能根据URL构建原请求
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(originalURI).build();
		DefaultSavedRequest.Builder builder = new DefaultSavedRequest.Builder();
		int port = getPort(uriComponents);
		//包装为新的Request
		return builder.setScheme(uriComponents.getScheme()).setServerName(uriComponents.getHost())
				.setRequestURI(uriComponents.getPath()).setQueryString(uriComponents.getQuery()).setServerPort(port)
				.setMethod(request.getMethod()).build();
	}

	private int getPort(UriComponents uriComponents) {
		int port = uriComponents.getPort();
		if (port != -1) {
			return port;
		}
		if ("https".equalsIgnoreCase(uriComponents.getScheme())) {
			return 443;
		}
		return 80;
	}

	@Override
	public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
		SavedRequest saved = this.getRequest(request, response);
		if (!this.matchesSavedRequest(request, saved)) {
			this.logger.debug("saved request doesn't match");
			return null;
		}
		this.removeRequest(request, response);
		return new SavedRequestAwareWrapper(saved, request);
	}

	@Override
	public void removeRequest(HttpServletRequest request, HttpServletResponse response) {
		Cookie removeSavedRequestCookie = new Cookie(COOKIE_NAME, "");
		removeSavedRequestCookie.setSecure(request.isSecure());
		removeSavedRequestCookie.setHttpOnly(true);
		removeSavedRequestCookie.setPath(getCookiePath(request));
		removeSavedRequestCookie.setMaxAge(0);
		response.addCookie(removeSavedRequestCookie);
	}

	private static String encodeCookie(String cookieValue) {
		return Base64.getEncoder().encodeToString(cookieValue.getBytes());
	}

	private static String decodeCookie(String encodedCookieValue) {
		return new String(Base64.getDecoder().decode(encodedCookieValue.getBytes()));
	}

	private static String getCookiePath(HttpServletRequest request) {
		String contextPath = request.getContextPath();
		return (!StringUtils.isEmpty(contextPath)) ? contextPath : "/";
	}

	/**
	 * 确定当前请求是否匹配缓存的请求
	 * <li>
	 *     与HttpSessionRequestCache的matchesSavedRequest方法相比，没有那么严格
	 *     只匹配了URL
	 * </li>
	 * @param request
	 * @param savedRequest
	 * @return
	 */
	private boolean matchesSavedRequest(HttpServletRequest request, SavedRequest savedRequest) {
		if (savedRequest == null) {
			return false;
		}
		String currentUrl = UrlUtils.buildFullRequestUrl(request);
		return savedRequest.getRedirectUrl().equals(currentUrl);
	}

	/**
	 * Allows selective use of saved requests for a subset of requests. By default any
	 * request will be cached by the {@code saveRequest} method.
	 * <p>
	 * If set, only matching requests will be cached.
	 * @param requestMatcher a request matching strategy which defines which requests
	 * should be cached.
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher should not be null");
		this.requestMatcher = requestMatcher;
	}

}

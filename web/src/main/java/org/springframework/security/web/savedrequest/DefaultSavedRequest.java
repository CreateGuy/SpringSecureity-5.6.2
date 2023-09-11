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

package org.springframework.security.web.savedrequest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.web.PortResolver;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

/**
 * 保存Request的信息，通常用在{@link RequestCache}
 */
public class DefaultSavedRequest implements SavedRequest {

	protected static final Log logger = LogFactory.getLog(DefaultSavedRequest.class);

	/**
	 * 这个和下面这个是需要缓存的请求头
	 */
	private static final String HEADER_IF_NONE_MATCH = "If-None-Match";

	private static final String HEADER_IF_MODIFIED_SINCE = "If-Modified-Since";

	private final ArrayList<SavedCookie> cookies = new ArrayList<>();

	/**
	 * 本次请求的环境，比如说zh_Cn, zh
	 */
	private final ArrayList<Locale> locales = new ArrayList<>();

	private final Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

	private final Map<String, String[]> parameters = new TreeMap<>();

	private final String contextPath;

	/**
	 * 请求方式
	 */
	private final String method;

	private final String pathInfo;

	private final String queryString;

	/**
	 * 一般情况是路径
	 */
	private final String requestURI;

	/**
	 * 协议://主机名:端口/路径
	 */
	private final String requestURL;

	/**
	 * 协议
	 */
	private final String scheme;

	private final String serverName;

	private final String servletPath;

	/**
	 * 请求的最初端口
	 */
	private final int serverPort;

	@SuppressWarnings("unchecked")
	public DefaultSavedRequest(HttpServletRequest request, PortResolver portResolver) {
		Assert.notNull(request, "Request required");
		Assert.notNull(portResolver, "PortResolver required");
		//添加Cookie
		addCookies(request.getCookies());
		//添加请求头
		Enumeration<String> names = request.getHeaderNames();
		while (names.hasMoreElements()) {
			String name = names.nextElement();
			//某些请求头不需要缓存
			if (HEADER_IF_MODIFIED_SINCE.equalsIgnoreCase(name) || HEADER_IF_NONE_MATCH.equalsIgnoreCase(name)) {
				continue;
			}
			Enumeration<String> values = request.getHeaders(name);
			while (values.hasMoreElements()) {
				this.addHeader(name, values.nextElement());
			}
		}
		//添加环境
		addLocales(request.getLocales());
		//添加参数
		addParameters(request.getParameterMap());
		// Primitives
		this.method = request.getMethod();
		this.pathInfo = request.getPathInfo();
		this.queryString = request.getQueryString();
		this.requestURI = request.getRequestURI();
		this.serverPort = portResolver.getServerPort(request);
		this.requestURL = request.getRequestURL().toString();
		this.scheme = request.getScheme();
		this.serverName = request.getServerName();
		this.contextPath = request.getContextPath();
		this.servletPath = request.getServletPath();
	}

	/**
	 * Private constructor invoked through Builder
	 */
	private DefaultSavedRequest(Builder builder) {
		this.contextPath = builder.contextPath;
		this.method = builder.method;
		this.pathInfo = builder.pathInfo;
		this.queryString = builder.queryString;
		this.requestURI = builder.requestURI;
		this.requestURL = builder.requestURL;
		this.scheme = builder.scheme;
		this.serverName = builder.serverName;
		this.servletPath = builder.servletPath;
		this.serverPort = builder.serverPort;
	}

	/**
	 * @since 4.2
	 */
	private void addCookies(Cookie[] cookies) {
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				this.addCookie(cookie);
			}
		}
	}

	private void addCookie(Cookie cookie) {
		this.cookies.add(new SavedCookie(cookie));
	}

	private void addHeader(String name, String value) {
		List<String> values = this.headers.computeIfAbsent(name, (key) -> new ArrayList<>());
		values.add(value);
	}

	/**
	 * @since 4.2
	 */
	private void addLocales(Enumeration<Locale> locales) {
		while (locales.hasMoreElements()) {
			Locale locale = locales.nextElement();
			this.addLocale(locale);
		}
	}

	private void addLocale(Locale locale) {
		this.locales.add(locale);
	}

	/**
	 * @since 4.2
	 */
	private void addParameters(Map<String, String[]> parameters) {
		if (!ObjectUtils.isEmpty(parameters)) {
			for (String paramName : parameters.keySet()) {
				Object paramValues = parameters.get(paramName);
				if (paramValues instanceof String[]) {
					this.addParameter(paramName, (String[]) paramValues);
				}
				else {
					logger.warn("ServletRequest.getParameterMap() returned non-String array");
				}
			}
		}
	}

	private void addParameter(String name, String[] values) {
		this.parameters.put(name, values);
	}

	/**
	 * 确定当前请求是否匹配缓存的请求
	 * @param request the actual request to be matched against this one
	 * @param portResolver used to obtain the server port of the request
	 * @return true if the request is deemed to match this one.
	 */
	public boolean doesRequestMatch(HttpServletRequest request, PortResolver portResolver) {
		if (!propertyEquals(this.pathInfo, request.getPathInfo())) {
			return false;
		}
		if (!propertyEquals(this.queryString, request.getQueryString())) {
			return false;
		}
		//确定是否和原请求Uri一样
		//因为认证成功后会重定向到原来的URL
		if (!propertyEquals(this.requestURI, request.getRequestURI())) {
			return false;
		}
		//保存的GET请求，不应该匹配非GET请求
		if (!"GET".equals(request.getMethod()) && "GET".equals(this.method)) {
			return false;
		}
		if (!propertyEquals(this.serverPort, portResolver.getServerPort(request))) {
			return false;
		}
		//确定是否和原请求URL一样
		//因为认证成功后会重定向到原来的URL
		if (!propertyEquals(this.requestURL, request.getRequestURL().toString())) {
			return false;
		}
		if (!propertyEquals(this.scheme, request.getScheme())) {
			return false;
		}
		if (!propertyEquals(this.serverName, request.getServerName())) {
			return false;
		}
		if (!propertyEquals(this.contextPath, request.getContextPath())) {
			return false;
		}
		return propertyEquals(this.servletPath, request.getServletPath());

	}

	public String getContextPath() {
		return this.contextPath;
	}

	@Override
	public List<Cookie> getCookies() {
		List<Cookie> cookieList = new ArrayList<>(this.cookies.size());
		for (SavedCookie savedCookie : this.cookies) {
			cookieList.add(savedCookie.getCookie());
		}
		return cookieList;
	}

	/**
	 * 返回当时重定向之前的Url
	 * @return the full URL of this request
	 */
	@Override
	public String getRedirectUrl() {
		return UrlUtils.buildFullRequestUrl(this.scheme, this.serverName, this.serverPort, this.requestURI,
				this.queryString);
	}

	@Override
	public Collection<String> getHeaderNames() {
		return this.headers.keySet();
	}

	@Override
	public List<String> getHeaderValues(String name) {
		List<String> values = this.headers.get(name);
		return (values != null) ? values : Collections.emptyList();
	}

	@Override
	public List<Locale> getLocales() {
		return this.locales;
	}

	@Override
	public String getMethod() {
		return this.method;
	}

	@Override
	public Map<String, String[]> getParameterMap() {
		return this.parameters;
	}

	public Collection<String> getParameterNames() {
		return this.parameters.keySet();
	}

	@Override
	public String[] getParameterValues(String name) {
		return this.parameters.get(name);
	}

	public String getPathInfo() {
		return this.pathInfo;
	}

	public String getQueryString() {
		return (this.queryString);
	}

	public String getRequestURI() {
		return (this.requestURI);
	}

	public String getRequestURL() {
		return this.requestURL;
	}

	public String getScheme() {
		return this.scheme;
	}

	public String getServerName() {
		return this.serverName;
	}

	public int getServerPort() {
		return this.serverPort;
	}

	public String getServletPath() {
		return this.servletPath;
	}

	private boolean propertyEquals(Object arg1, Object arg2) {
		if ((arg1 == null) && (arg2 == null)) {
			return true;
		}
		if (arg1 == null || arg2 == null) {
			return false;
		}
		if (arg1.equals(arg2)) {
			return true;
		}
		return false;
	}

	@Override
	public String toString() {
		return "DefaultSavedRequest [" + getRedirectUrl() + "]";
	}

	/**
	 * @since 4.2
	 */
	@JsonIgnoreProperties(ignoreUnknown = true)
	@JsonPOJOBuilder(withPrefix = "set")
	public static class Builder {

		private List<SavedCookie> cookies = null;

		private List<Locale> locales = null;

		private Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

		private Map<String, String[]> parameters = new TreeMap<>();

		private String contextPath;

		private String method;

		private String pathInfo;

		private String queryString;

		private String requestURI;

		private String requestURL;

		private String scheme;

		private String serverName;

		private String servletPath;

		private int serverPort = 80;

		public Builder setCookies(List<SavedCookie> cookies) {
			this.cookies = cookies;
			return this;
		}

		public Builder setLocales(List<Locale> locales) {
			this.locales = locales;
			return this;
		}

		public Builder setHeaders(Map<String, List<String>> header) {
			this.headers.putAll(header);
			return this;
		}

		public Builder setParameters(Map<String, String[]> parameters) {
			this.parameters = parameters;
			return this;
		}

		public Builder setContextPath(String contextPath) {
			this.contextPath = contextPath;
			return this;
		}

		public Builder setMethod(String method) {
			this.method = method;
			return this;
		}

		public Builder setPathInfo(String pathInfo) {
			this.pathInfo = pathInfo;
			return this;
		}

		public Builder setQueryString(String queryString) {
			this.queryString = queryString;
			return this;
		}

		public Builder setRequestURI(String requestURI) {
			this.requestURI = requestURI;
			return this;
		}

		public Builder setRequestURL(String requestURL) {
			this.requestURL = requestURL;
			return this;
		}

		public Builder setScheme(String scheme) {
			this.scheme = scheme;
			return this;
		}

		public Builder setServerName(String serverName) {
			this.serverName = serverName;
			return this;
		}

		public Builder setServletPath(String servletPath) {
			this.servletPath = servletPath;
			return this;
		}

		public Builder setServerPort(int serverPort) {
			this.serverPort = serverPort;
			return this;
		}

		public DefaultSavedRequest build() {
			DefaultSavedRequest savedRequest = new DefaultSavedRequest(this);
			if (!ObjectUtils.isEmpty(this.cookies)) {
				for (SavedCookie cookie : this.cookies) {
					savedRequest.addCookie(cookie.getCookie());
				}
			}
			if (!ObjectUtils.isEmpty(this.locales)) {
				savedRequest.locales.addAll(this.locales);
			}
			savedRequest.addParameters(this.parameters);
			this.headers.remove(HEADER_IF_MODIFIED_SINCE);
			this.headers.remove(HEADER_IF_NONE_MATCH);
			for (Map.Entry<String, List<String>> entry : this.headers.entrySet()) {
				String headerName = entry.getKey();
				List<String> headerValues = entry.getValue();
				for (String headerValue : headerValues) {
					savedRequest.addHeader(headerName, headerValue);
				}
			}
			return savedRequest;
		}

	}

}

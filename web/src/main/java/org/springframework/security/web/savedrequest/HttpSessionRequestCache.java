/*
 * Copyright 2002-2016 the original author or authors.
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * 在HttpSession中存储某次请求的缓冲器
 * 也是SpringSecurity默认的请求缓存器策略
 * */
public class HttpSessionRequestCache implements RequestCache {

	static final String SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";

	protected final Log logger = LogFactory.getLog(this.getClass());

	private PortResolver portResolver = new PortResolverImpl();

	private boolean createSessionAllowed = true;

	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;

	private String sessionAttrName = SAVED_REQUEST;

	/**
	 * Stores the current request, provided the configuration properties allow it.
	 */
	@Override
	public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
		if (!this.requestMatcher.matches(request)) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(
						LogMessage.format("Did not save request since it did not match [%s]", this.requestMatcher));
			}
			return;
		}
		DefaultSavedRequest savedRequest = new DefaultSavedRequest(request, this.portResolver);
		if (this.createSessionAllowed || request.getSession(false) != null) {
			// Store the HTTP request itself. Used by
			// AbstractAuthenticationProcessingFilter
			// for redirection after successful authentication (SEC-29)
			request.getSession().setAttribute(this.sessionAttrName, savedRequest);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Saved request %s to session", savedRequest.getRedirectUrl()));
			}
		}
		else {
			this.logger.trace("Did not save request since there's no session and createSessionAllowed is false");
		}
	}

	@Override
	public SavedRequest getRequest(HttpServletRequest currentRequest, HttpServletResponse response) {
		HttpSession session = currentRequest.getSession(false);
		return (session != null) ? (SavedRequest) session.getAttribute(this.sessionAttrName) : null;
	}

	/**
	 * 从HttpSession中删除请求缓存
	 * @param currentRequest
	 * @param response
	 */
	@Override
	public void removeRequest(HttpServletRequest currentRequest, HttpServletResponse response) {
		HttpSession session = currentRequest.getSession(false);
		if (session != null) {
			this.logger.trace("Removing DefaultSavedRequest from session if present");
			session.removeAttribute(this.sessionAttrName);
		}
	}

	/**
	 * 如果与当前请求匹配，则返回保存的请求的包装器，保存的请求应该从缓存中删除。
	 * @param request
	 * @param response
	 * @return
	 */
	@Override
	public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) {
		//获得保存的请求缓存
		SavedRequest saved = getRequest(request, response);
		//为空就不包装
		if (saved == null) {
			this.logger.trace("No saved request");
			return null;
		}
		//确定当前请求是否匹配缓存的请求
		if (!matchesSavedRequest(request, saved)) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Did not match request %s to the saved one %s",
						UrlUtils.buildRequestUrl(request), saved));
			}
			return null;
		}
		//移除缓存的请求
		removeRequest(request, response);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Loaded matching saved request %s", saved.getRedirectUrl()));
		}
		//进行包装
		return new SavedRequestAwareWrapper(saved, request);
	}

	/**
	 * 确定当前请求是否匹配缓存的请求
	 * @param request
	 * @param savedRequest
	 * @return
	 */
	private boolean matchesSavedRequest(HttpServletRequest request, SavedRequest savedRequest) {
		//一般保存的就是这个类型
		if (savedRequest instanceof DefaultSavedRequest) {
			DefaultSavedRequest defaultSavedRequest = (DefaultSavedRequest) savedRequest;
			//确定当前请求是否匹配缓存的请求
			return defaultSavedRequest.doesRequestMatch(request, this.portResolver);
		}
		//构建完整的请求
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
		this.requestMatcher = requestMatcher;
	}

	/**
	 * If <code>true</code>, indicates that it is permitted to store the target URL and
	 * exception information in a new <code>HttpSession</code> (the default). In
	 * situations where you do not wish to unnecessarily create <code>HttpSession</code>s
	 * - because the user agent will know the failed URL, such as with BASIC or Digest
	 * authentication - you may wish to set this property to <code>false</code>.
	 */
	public void setCreateSessionAllowed(boolean createSessionAllowed) {
		this.createSessionAllowed = createSessionAllowed;
	}

	public void setPortResolver(PortResolver portResolver) {
		this.portResolver = portResolver;
	}

	/**
	 * If the {@code sessionAttrName} property is set, the request is stored in the
	 * session using this attribute name. Default is "SPRING_SECURITY_SAVED_REQUEST".
	 * @param sessionAttrName a new session attribute name.
	 * @since 4.2.1
	 */
	public void setSessionAttrName(String sessionAttrName) {
		this.sessionAttrName = sessionAttrName;
	}

}

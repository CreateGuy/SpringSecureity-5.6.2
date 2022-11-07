/*
 * Copyright 2010-2016 the original author or authors.
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

package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.LinkedHashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.ELRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEditor;
import org.springframework.util.Assert;

/**
 * 代表性的身份认证入口点，它通过请求匹配器择一个具体的身份认证入口点
 */
public class DelegatingAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {

	private static final Log logger = LogFactory.getLog(DelegatingAuthenticationEntryPoint.class);

	/**
	 * 所有的身份认证入口点
	 */
	private final LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints;

	/**
	 * 默认的身份认证入口点
	 */
	private AuthenticationEntryPoint defaultEntryPoint;

	public DelegatingAuthenticationEntryPoint(LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints) {
		this.entryPoints = entryPoints;
	}

	/**
	 * 遍历所有身份认证入口点，选择执行某一个身份认证入口点
	 * @param request that resulted in an <code>AuthenticationException</code>
	 * @param response so that the user agent can begin authentication
	 * @param authException 权限判断的时候抛出的异常
	 * @throws IOException
	 * @throws ServletException
	 */
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		for (RequestMatcher requestMatcher : this.entryPoints.keySet()) {
			logger.debug(LogMessage.format("Trying to match using %s", requestMatcher));
			//进行匹配
			if (requestMatcher.matches(request)) {
				AuthenticationEntryPoint entryPoint = this.entryPoints.get(requestMatcher);
				logger.debug(LogMessage.format("Match found! Executing %s", entryPoint));
				entryPoint.commence(request, response, authException);
				return;
			}
		}
		logger.debug(LogMessage.format("No match found. Using default entry point %s", this.defaultEntryPoint));
		//无法通过请求匹配器匹配身份认证入口点，就用默认的
		this.defaultEntryPoint.commence(request, response, authException);
	}

	/**
	 * EntryPoint which is used when no RequestMatcher returned true
	 */
	public void setDefaultEntryPoint(AuthenticationEntryPoint defaultEntryPoint) {
		this.defaultEntryPoint = defaultEntryPoint;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notEmpty(this.entryPoints, "entryPoints must be specified");
		Assert.notNull(this.defaultEntryPoint, "defaultEntryPoint must be specified");
	}

}

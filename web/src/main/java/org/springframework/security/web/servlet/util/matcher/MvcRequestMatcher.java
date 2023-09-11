/*
 * Copyright 2012-2021 the original author or authors.
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

package org.springframework.security.web.servlet.util.matcher;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestVariablesExtractor;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import org.springframework.web.servlet.handler.MatchableHandlerMapping;
import org.springframework.web.servlet.handler.RequestMatchResult;
import org.springframework.web.util.UrlPathHelper;

/**
 * 一个使用Spring MVC的HandlerMappingIntrospector来匹配路径和提取变量的RequestMatcher
 * <ul>
 *     <li>
 *         是基于Url+请求方式的
 *     </li>
 *     <li>
 *         如果请求Url是/a, 与AntPathRequestMatcher的区别在于这个还能匹配/a.html,/a.abc之类的
 *     </li>
 * </ul>
 */
public class MvcRequestMatcher implements RequestMatcher, RequestVariablesExtractor {

	private final DefaultMatcher defaultMatcher = new DefaultMatcher();

	/**
	 * Spring MVC的 HandlerMappingIntrospector
	 * 里面有全部的HandlerMapping
	 */
	private final HandlerMappingIntrospector introspector;

	/**
	 * 匹配的请求url
	 */
	private final String pattern;

	/**
	 * 请求方式
	 */
	private HttpMethod method;

	private String servletPath;

	public MvcRequestMatcher(HandlerMappingIntrospector introspector, String pattern) {
		this.introspector = introspector;
		this.pattern = pattern;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		//判断请求方式和servletPath是否相同
		if (notMatchMethodOrServletPath(request)) {
			return false;
		}
		MatchableHandlerMapping mapping = getMapping(request);
		if (mapping == null) {
			return this.defaultMatcher.matches(request);
		}
		RequestMatchResult matchResult = mapping.match(request, this.pattern);
		//必须要存在这个url对应的方法
		return matchResult != null;
	}

	@Override
	@Deprecated
	public Map<String, String> extractUriTemplateVariables(HttpServletRequest request) {
		return matcher(request).getVariables();
	}

	@Override
	public MatchResult matcher(HttpServletRequest request) {
		if (notMatchMethodOrServletPath(request)) {
			return MatchResult.notMatch();
		}
		MatchableHandlerMapping mapping = getMapping(request);
		if (mapping == null) {
			return this.defaultMatcher.matcher(request);
		}
		RequestMatchResult result = mapping.match(request, this.pattern);
		return (result != null) ? MatchResult.match(result.extractUriTemplateVariables()) : MatchResult.notMatch();
	}

	/**
	 * 判断请求方式和servletPath是否相同
	 * @param request
	 * @return
	 */
	private boolean notMatchMethodOrServletPath(HttpServletRequest request) {
		return this.method != null && !this.method.name().equals(request.getMethod())
				|| this.servletPath != null && !this.servletPath.equals(request.getServletPath());
	}

	private MatchableHandlerMapping getMapping(HttpServletRequest request) {
		try {
			return this.introspector.getMatchableHandlerMapping(request);
		}
		catch (Throwable ex) {
			return null;
		}
	}

	/**
	 * @param method the method to set
	 */
	public void setMethod(HttpMethod method) {
		this.method = method;
	}

	/**
	 * The servlet path to match on. The default is undefined which means any servlet
	 * path.
	 * @param servletPath the servletPath to set
	 */
	public void setServletPath(String servletPath) {
		this.servletPath = servletPath;
	}

	protected final String getServletPath() {
		return this.servletPath;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Mvc [pattern='").append(this.pattern).append("'");
		if (this.servletPath != null) {
			sb.append(", servletPath='").append(this.servletPath).append("'");
		}
		if (this.method != null) {
			sb.append(", ").append(this.method);
		}
		sb.append("]");
		return sb.toString();
	}

	/**
	 * 默认的请求匹配器
	 */
	private class DefaultMatcher implements RequestMatcher {

		private final UrlPathHelper pathHelper = new UrlPathHelper();

		private final PathMatcher pathMatcher = new AntPathMatcher();

		@Override
		public boolean matches(HttpServletRequest request) {
			String lookupPath = this.pathHelper.getLookupPathForRequest(request);
			return matches(lookupPath);
		}

		private boolean matches(String lookupPath) {
			return this.pathMatcher.match(MvcRequestMatcher.this.pattern, lookupPath);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			String lookupPath = this.pathHelper.getLookupPathForRequest(request);
			if (matches(lookupPath)) {
				Map<String, String> variables = this.pathMatcher
						.extractUriTemplateVariables(MvcRequestMatcher.this.pattern, lookupPath);
				return MatchResult.match(variables);
			}
			return MatchResult.notMatch();
		}

	}

}

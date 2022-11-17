/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.authentication.ui;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 生成一个默认的注销页面
 */
public class DefaultLogoutPageGeneratingFilter extends OncePerRequestFilter {

	/**
	 * 请求匹配器：用于匹配是否是登出请求
	 * 默认的登出和登出页都是GET方式的/logout，所以默认是看不到登出页的，只有改变登出的Url或者方式
	 */
	private RequestMatcher matcher = new AntPathRequestMatcher("/logout", "GET");

	/**
	 * 解析隐藏域的函数，一般是获取Csrf令牌的
	 */
	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = (request) -> Collections.emptyMap();

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		//确定是否是登出请求
		if (this.matcher.matches(request)) {
			renderLogout(request, response);
		}
		else {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Did not render default logout page since request did not match [%s]",
						this.matcher));
			}
			filterChain.doFilter(request, response);
		}
	}

	/**
	 * 生成登出页
	 * @param request
	 * @param response
	 * @throws IOException
	 */
	private void renderLogout(HttpServletRequest request, HttpServletResponse response) throws IOException {
		StringBuilder sb = new StringBuilder();
		sb.append("<!DOCTYPE html>\n");
		sb.append("<html lang=\"en\">\n");
		sb.append("  <head>\n");
		sb.append("    <meta charset=\"utf-8\">\n");
		sb.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n");
		sb.append("    <meta name=\"description\" content=\"\">\n");
		sb.append("    <meta name=\"author\" content=\"\">\n");
		sb.append("    <title>Confirm Log Out?</title>\n");
		sb.append("    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" "
				+ "rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" "
				+ "crossorigin=\"anonymous\">\n");
		sb.append("    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" "
				+ "rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n");
		sb.append("  </head>\n");
		sb.append("  <body>\n");
		sb.append("     <div class=\"container\">\n");
		sb.append("      <form class=\"form-signin\" method=\"post\" action=\"" + request.getContextPath()
				+ "/logout\">\n");
		sb.append("        <h2 class=\"form-signin-heading\">Are you sure you want to log out?</h2>\n");
		sb.append(renderHiddenInputs(request)
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Log Out</button>\n");
		sb.append("      </form>\n");
		sb.append("    </div>\n");
		sb.append("  </body>\n");
		sb.append("</html>");
		response.setContentType("text/html;charset=UTF-8");
		response.getWriter().write(sb.toString());
	}

	/**
	 * 设置一个函数，用于解析隐藏输入的Map，其中键是输入的名称，值是输入的值。这通常用于解析CSRF令牌。
	 * @param resolveHiddenInputs
	 */
	public void setResolveHiddenInputs(Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs) {
		Assert.notNull(resolveHiddenInputs, "resolveHiddenInputs cannot be null");
		this.resolveHiddenInputs = resolveHiddenInputs;
	}

	/**
	 * 设置隐藏域参数，通常是Csrf令牌
	 * @param request
	 * @return
	 */
	private String renderHiddenInputs(HttpServletRequest request) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, String> input : this.resolveHiddenInputs.apply(request).entrySet()) {
			sb.append("<input name=\"");
			sb.append(input.getKey());
			sb.append("\" type=\"hidden\" value=\"");
			sb.append(input.getValue());
			sb.append("\" />\n");
		}
		return sb.toString();
	}

}

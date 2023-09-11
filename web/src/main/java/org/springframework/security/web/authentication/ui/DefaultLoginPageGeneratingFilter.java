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
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.HtmlUtils;

/**
 *
 * 在用户没有配置登录页面的情况下，创建一个登录页
 */
public class DefaultLoginPageGeneratingFilter extends GenericFilterBean {

	/**
	 * 默认的登录页请求Url
	 */
	public static final String DEFAULT_LOGIN_PAGE_URL = "/login";

	public static final String ERROR_PARAMETER_NAME = "error";

	/**
	 * 登录页请求Url
	 */
	private String loginPageUrl;

	/**
	 * 登录成功后的跳转的Url
	 */
	private String logoutSuccessUrl;

	/**
	 * 登录失败后的跳转的Url
	 */
	private String failureUrl;

	/**
	 * 登录页是否开启表单登录
	 * 如果为True就会添加对应html代码，下面三个一样的
	 */
	private boolean formLoginEnabled;

	private boolean openIdEnabled;

	private boolean oauth2LoginEnabled;

	private boolean saml2LoginEnabled;

	/**
	 * 表单登录中：进行身份认证的Url
	 */
	private String authenticationUrl;

	/**
	 * 表单登录中：进用户名参数名
	 */
	private String usernameParameter;

	/**
	 * 表单登录中：进密码参数名
	 */
	private String passwordParameter;

	/**
	 * 表单登录中：进记住我参数名
	 */
	private String rememberMeParameter;

	/**
	 * 下面都是其他登录方式的参数，不懂，没了解过
	 */
	private String openIDauthenticationUrl;

	private String openIDusernameParameter;

	private String openIDrememberMeParameter;

	private Map<String, String> oauth2AuthenticationUrlToClientName;

	private Map<String, String> saml2AuthenticationUrlToProviderName;

	/**
	 * 通常是获得CSRF令牌的函数
	 */
	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = (request) -> Collections.emptyMap();

	public DefaultLoginPageGeneratingFilter() {
	}

	public DefaultLoginPageGeneratingFilter(AbstractAuthenticationProcessingFilter filter) {
		if (filter instanceof UsernamePasswordAuthenticationFilter) {
			init((UsernamePasswordAuthenticationFilter) filter, null);
		}
		else {
			init(null, filter);
		}
	}

	public DefaultLoginPageGeneratingFilter(UsernamePasswordAuthenticationFilter authFilter,
			AbstractAuthenticationProcessingFilter openIDFilter) {
		init(authFilter, openIDFilter);
	}

	/**
	 * 利用传入的认证过滤器对当前过滤器进行初始化
	 * @param authFilter
	 * @param openIDFilter
	 */
	private void init(UsernamePasswordAuthenticationFilter authFilter,
			AbstractAuthenticationProcessingFilter openIDFilter) {
		this.loginPageUrl = DEFAULT_LOGIN_PAGE_URL;
		this.logoutSuccessUrl = DEFAULT_LOGIN_PAGE_URL + "?logout";
		this.failureUrl = DEFAULT_LOGIN_PAGE_URL + "?" + ERROR_PARAMETER_NAME;
		if (authFilter != null) {
			initAuthFilter(authFilter);
		}
		if (openIDFilter != null) {
			initOpenIdFilter(openIDFilter);
		}
	}

	/**
	 * 利用UsernamePasswordAuthenticationFilter进行初始化
	 * @param authFilter
	 */
	private void initAuthFilter(UsernamePasswordAuthenticationFilter authFilter) {
		//开启表单登录
		this.formLoginEnabled = true;
		//设置用户名和密码的参数名称
		this.usernameParameter = authFilter.getUsernameParameter();
		this.passwordParameter = authFilter.getPasswordParameter();
		//如果开启了记住我功能，就是在记住我参数名称
		if (authFilter.getRememberMeServices() instanceof AbstractRememberMeServices) {
			this.rememberMeParameter = ((AbstractRememberMeServices) authFilter.getRememberMeServices()).getParameter();
		}
	}

	private void initOpenIdFilter(AbstractAuthenticationProcessingFilter openIDFilter) {
		this.openIdEnabled = true;
		this.openIDusernameParameter = "openid_identifier";
		if (openIDFilter.getRememberMeServices() instanceof AbstractRememberMeServices) {
			this.openIDrememberMeParameter = ((AbstractRememberMeServices) openIDFilter.getRememberMeServices())
					.getParameter();
		}
	}

	/**
	 * 设置一个函数，用于获得隐藏输入的Map，其中键是输入的名称，值是输入的值。这通常用于获得CSRF令牌
	 */
	public void setResolveHiddenInputs(Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs) {
		Assert.notNull(resolveHiddenInputs, "resolveHiddenInputs cannot be null");
		this.resolveHiddenInputs = resolveHiddenInputs;
	}

	/**
	 * 确定当前过滤器是否需要添加到HttpSecurity中
	 * 比如说：用户设置了登录页的时候，这里就会返回false
	 * @return
	 */
	public boolean isEnabled() {
		return this.formLoginEnabled || this.openIdEnabled || this.oauth2LoginEnabled || this.saml2LoginEnabled;
	}

	public void setLogoutSuccessUrl(String logoutSuccessUrl) {
		this.logoutSuccessUrl = logoutSuccessUrl;
	}

	public String getLoginPageUrl() {
		return this.loginPageUrl;
	}

	public void setLoginPageUrl(String loginPageUrl) {
		this.loginPageUrl = loginPageUrl;
	}

	public void setFailureUrl(String failureUrl) {
		this.failureUrl = failureUrl;
	}

	public void setFormLoginEnabled(boolean formLoginEnabled) {
		this.formLoginEnabled = formLoginEnabled;
	}

	public void setOpenIdEnabled(boolean openIdEnabled) {
		this.openIdEnabled = openIdEnabled;
	}

	public void setOauth2LoginEnabled(boolean oauth2LoginEnabled) {
		this.oauth2LoginEnabled = oauth2LoginEnabled;
	}

	public void setSaml2LoginEnabled(boolean saml2LoginEnabled) {
		this.saml2LoginEnabled = saml2LoginEnabled;
	}

	public void setAuthenticationUrl(String authenticationUrl) {
		this.authenticationUrl = authenticationUrl;
	}

	public void setUsernameParameter(String usernameParameter) {
		this.usernameParameter = usernameParameter;
	}

	public void setPasswordParameter(String passwordParameter) {
		this.passwordParameter = passwordParameter;
	}

	public void setRememberMeParameter(String rememberMeParameter) {
		this.rememberMeParameter = rememberMeParameter;
		this.openIDrememberMeParameter = rememberMeParameter;
	}

	public void setOpenIDauthenticationUrl(String openIDauthenticationUrl) {
		this.openIDauthenticationUrl = openIDauthenticationUrl;
	}

	public void setOpenIDusernameParameter(String openIDusernameParameter) {
		this.openIDusernameParameter = openIDusernameParameter;
	}

	public void setOauth2AuthenticationUrlToClientName(Map<String, String> oauth2AuthenticationUrlToClientName) {
		this.oauth2AuthenticationUrlToClientName = oauth2AuthenticationUrlToClientName;
	}

	public void setSaml2AuthenticationUrlToProviderName(Map<String, String> saml2AuthenticationUrlToProviderName) {
		this.saml2AuthenticationUrlToProviderName = saml2AuthenticationUrlToProviderName;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//是否是认证失败Url的请求
		boolean loginError = isErrorPage(request);
		//是否是登出成功的请求
		boolean logoutSuccess = isLogoutSuccess(request);
		//判断是否需要生产登录页
		if (isLoginUrlRequest(request) || loginError || logoutSuccess) {
			String loginPageHtml = generateLoginPageHtml(request, loginError, logoutSuccess);
			response.setContentType("text/html;charset=UTF-8");
			response.setContentLength(loginPageHtml.getBytes(StandardCharsets.UTF_8).length);
			response.getWriter().write(loginPageHtml);
			return;
		}
		chain.doFilter(request, response);
	}

	/**
	 * 生产登录页的Html代码
	 * @param request
	 * @param loginError
	 * @param logoutSuccess
	 * @return
	 */
	private String generateLoginPageHtml(HttpServletRequest request, boolean loginError, boolean logoutSuccess) {
		String errorMsg = "Invalid credentials";
		//当是登录(认证)失败的时候，填充错误原因
		if (loginError) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				AuthenticationException ex = (AuthenticationException) session
						.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
				errorMsg = (ex != null) ? ex.getMessage() : "Invalid credentials";
			}
		}
		String contextPath = request.getContextPath();
		StringBuilder sb = new StringBuilder();
		sb.append("<!DOCTYPE html>\n");
		sb.append("<html lang=\"en\">\n");
		sb.append("  <head>\n");
		sb.append("    <meta charset=\"utf-8\">\n");
		sb.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n");
		sb.append("    <meta name=\"description\" content=\"\">\n");
		sb.append("    <meta name=\"author\" content=\"\">\n");
		sb.append("    <title>Please sign in</title>\n");
		sb.append("    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" "
				+ "rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n");
		sb.append("    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" "
				+ "rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n");
		sb.append("  </head>\n");
		sb.append("  <body>\n");
		sb.append("     <div class=\"container\">\n");

		//开起了表单登录，填充有关的代码
		if (this.formLoginEnabled) {
			sb.append("      <form class=\"form-signin\" method=\"post\" action=\"" + contextPath
					+ this.authenticationUrl + "\">\n");
			sb.append("        <h2 class=\"form-signin-heading\">Please sign in</h2>\n");
			sb.append(createError(loginError, errorMsg) + createLogoutSuccess(logoutSuccess) + "        <p>\n");
			sb.append("          <label for=\"username\" class=\"sr-only\">Username</label>\n");
			sb.append("          <input type=\"text\" id=\"username\" name=\"" + this.usernameParameter
					+ "\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n");
			sb.append("        </p>\n");
			sb.append("        <p>\n");
			sb.append("          <label for=\"password\" class=\"sr-only\">Password</label>\n");
			sb.append("          <input type=\"password\" id=\"password\" name=\"" + this.passwordParameter
					+ "\" class=\"form-control\" placeholder=\"Password\" required>\n");
			sb.append("        </p>\n");
			sb.append(createRememberMe(this.rememberMeParameter) + renderHiddenInputs(request));
			sb.append("        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n");
			sb.append("      </form>\n");
		}
		if (this.openIdEnabled) {
			sb.append("      <form name=\"oidf\" class=\"form-signin\" method=\"post\" action=\"" + contextPath
					+ this.openIDauthenticationUrl + "\">\n");
			sb.append("        <h2 class=\"form-signin-heading\">Login with OpenID Identity</h2>\n");
			sb.append(createError(loginError, errorMsg) + createLogoutSuccess(logoutSuccess) + "        <p>\n");
			sb.append("          <label for=\"username\" class=\"sr-only\">Identity</label>\n");
			sb.append("          <input type=\"text\" id=\"username\" name=\"" + this.openIDusernameParameter
					+ "\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n");
			sb.append("        </p>\n");
			sb.append(createRememberMe(this.openIDrememberMeParameter) + renderHiddenInputs(request));
			sb.append("        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n");
			sb.append("      </form>\n");
		}
		if (this.oauth2LoginEnabled) {
			sb.append("<h2 class=\"form-signin-heading\">Login with OAuth 2.0</h2>");
			sb.append(createError(loginError, errorMsg));
			sb.append(createLogoutSuccess(logoutSuccess));
			sb.append("<table class=\"table table-striped\">\n");
			for (Map.Entry<String, String> clientAuthenticationUrlToClientName : this.oauth2AuthenticationUrlToClientName
					.entrySet()) {
				sb.append(" <tr><td>");
				String url = clientAuthenticationUrlToClientName.getKey();
				sb.append("<a href=\"").append(contextPath).append(url).append("\">");
				String clientName = HtmlUtils.htmlEscape(clientAuthenticationUrlToClientName.getValue());
				sb.append(clientName);
				sb.append("</a>");
				sb.append("</td></tr>\n");
			}
			sb.append("</table>\n");
		}
		if (this.saml2LoginEnabled) {
			sb.append("<h2 class=\"form-signin-heading\">Login with SAML 2.0</h2>");
			sb.append(createError(loginError, errorMsg));
			sb.append(createLogoutSuccess(logoutSuccess));
			sb.append("<table class=\"table table-striped\">\n");
			for (Map.Entry<String, String> relyingPartyUrlToName : this.saml2AuthenticationUrlToProviderName
					.entrySet()) {
				sb.append(" <tr><td>");
				String url = relyingPartyUrlToName.getKey();
				sb.append("<a href=\"").append(contextPath).append(url).append("\">");
				String partyName = HtmlUtils.htmlEscape(relyingPartyUrlToName.getValue());
				sb.append(partyName);
				sb.append("</a>");
				sb.append("</td></tr>\n");
			}
			sb.append("</table>\n");
		}
		sb.append("</div>\n");
		sb.append("</body></html>");
		return sb.toString();
	}

	/**
	 * 填充隐藏预的属性，通常是Csrf令牌
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

	/**
	 * 判断是否需要创建RememberMe参数
	 * @param paramName
	 * @return
	 */
	private String createRememberMe(String paramName) {
		if (paramName == null) {
			return "";
		}
		return "<p><input type='checkbox' name='" + paramName + "'/> Remember me on this computer.</p>\n";
	}

	/**
	 * 判断是否是登出成功Url
	 * @param request
	 * @return
	 */
	private boolean isLogoutSuccess(HttpServletRequest request) {
		return this.logoutSuccessUrl != null && matches(request, this.logoutSuccessUrl);
	}

	/**
	 * 判断是否是登录页Url
	 * @param request
	 * @return
	 */
	private boolean isLoginUrlRequest(HttpServletRequest request) {
		return matches(request, this.loginPageUrl);
	}

	/**
	 * 判断是否是认证失败Url的请求
	 * @param request
	 * @return
	 */
	private boolean isErrorPage(HttpServletRequest request) {
		return matches(request, this.failureUrl);
	}

	private static String createError(boolean isError, String message) {
		if (!isError) {
			return "";
		}
		return "<div class=\"alert alert-danger\" role=\"alert\">" + HtmlUtils.htmlEscape(message) + "</div>";
	}

	private static String createLogoutSuccess(boolean isLogoutSuccess) {
		if (!isLogoutSuccess) {
			return "";
		}
		return "<div class=\"alert alert-success\" role=\"alert\">You have been signed out</div>";
	}

	/**
	 * 匹配请求的Url是否和传入的一致
	 * @param request
	 * @param url
	 * @return
	 */
	private boolean matches(HttpServletRequest request, String url) {
		if (!"GET".equals(request.getMethod()) || url == null) {
			return false;
		}
		String uri = request.getRequestURI();
		int pathParamIndex = uri.indexOf(';');
		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}
		if (request.getQueryString() != null) {
			uri += "?" + request.getQueryString();
		}
		if ("".equals(request.getContextPath())) {
			return uri.equals(url);
		}
		return uri.equals(request.getContextPath() + url);
	}

}

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

package org.springframework.security.web.authentication.rememberme;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Base class for RememberMeServices implementations.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author Eddú Meléndez
 * @author Onur Kagan Ozcan
 * @since 2.0
 */
public abstract class AbstractRememberMeServices
		implements RememberMeServices, InitializingBean, LogoutHandler, MessageSourceAware {

	public static final String SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY = "remember-me";

	public static final String DEFAULT_PARAMETER = "remember-me";

	/**
	 * 默认记住我令牌过期时间
	 */
	public static final int TWO_WEEKS_S = 1209600;

	/**
	 * 记住我令牌中的几个参数的分隔符
	 */
	private static final String DELIMITER = ":";

	protected final Log logger = LogFactory.getLog(getClass());

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	/**
	 * 用户详情服务
	 */
	private UserDetailsService userDetailsService;

	/**
	 * UserDetails的检查器
	 */
	private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

	/**
	 * 认证信息详情源
	 */
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	/**
	 * 记住我令牌名称
	 */
	private String cookieName = SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY;

	/**
	 * 指定记住我参令牌可访问的域名
	 */
	private String cookieDomain;

	/**
	 * 一般情况是登录页中的是否开启记住我功能的标志位
	 */
	private String parameter = DEFAULT_PARAMETER;

	/**
	 * 是否一直需要携带记住我令牌
	 * <url>
	 *     <li>
	 *         true：都携带记住我令牌
	 *     </li>
	 *     <li>
	 *         false：看客户端是否携带了记住我参数
	 *     </li>
	 * </url>
	 */
	private boolean alwaysRemember;

	/**
	 * 生成记住我令牌的秘钥
	 */
	private String key;

	/**
	 * 记住我令牌过期时间
	 */
	private int tokenValiditySeconds = TWO_WEEKS_S;

	/**
	 * 为true时必须通过https请求才能携带cookie中的信息
	 */
	private Boolean useSecureCookie = null;

	/**
	 * 权限映射接口
	 */
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	protected AbstractRememberMeServices(String key, UserDetailsService userDetailsService) {
		Assert.hasLength(key, "key cannot be empty or null");
		Assert.notNull(userDetailsService, "UserDetailsService cannot be null");
		this.key = key;
		this.userDetailsService = userDetailsService;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.hasLength(this.key, "key cannot be empty or null");
		Assert.notNull(this.userDetailsService, "A UserDetailsService is required");
	}

	/**
	 * 获得记住我认证对象
	 * <ul>
	 *     <li>
	 *         1、获得记住我令牌
	 *     </li>
	 *     <li>
	 *         2、解析记住我令牌，变成用户对象
	 *     </li>
	 *     <li>
	 *         3、根据用户对象，构建记住我认证对象
	 *     </li>
	 * </ul>
	 */
	@Override
	public final Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
		//获取记住我令牌
		String rememberMeCookie = extractRememberMeCookie(request);
		if (rememberMeCookie == null) {
			return null;
		}
		this.logger.debug("Remember-me cookie detected");
		//记住我令牌不能为空
		if (rememberMeCookie.length() == 0) {
			this.logger.debug("Cookie was empty");
			//将生存时间设置为0，以禁用记住我认证
			cancelCookie(request, response);
			return null;
		}
		try {
			//将记住我令牌进行Base64解码
			String[] cookieTokens = decodeCookie(rememberMeCookie);
			//记住我令牌转换为用户对象
			UserDetails user = processAutoLoginCookie(cookieTokens, request, response);
			//进行检查
			this.userDetailsChecker.check(user);
			this.logger.debug("Remember-me cookie accepted");
			//创建记住我认证对象
			return createSuccessfulAuthentication(request, user);
		}
		catch (CookieTheftException ex) {
			cancelCookie(request, response);
			throw ex;
		}
		catch (UsernameNotFoundException ex) {
			this.logger.debug("Remember-me login was valid but corresponding user not found.", ex);
		}
		catch (InvalidCookieException ex) {
			this.logger.debug("Invalid remember-me cookie: " + ex.getMessage());
		}
		catch (AccountStatusException ex) {
			this.logger.debug("Invalid UserDetails: " + ex.getMessage());
		}
		catch (RememberMeAuthenticationException ex) {
			this.logger.debug(ex.getMessage());
		}
		cancelCookie(request, response);
		return null;
	}

	/**
	 * 获取记住我令牌
	 */
	protected String extractRememberMeCookie(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		if ((cookies == null) || (cookies.length == 0)) {
			return null;
		}
		for (Cookie cookie : cookies) {
			if (this.cookieName.equals(cookie.getName())) {
				return cookie.getValue();
			}
		}
		return null;
	}

	/**
	 * 创建记住我认证对象
	 * @param request
	 * @param user
	 * @return
	 */
	protected Authentication createSuccessfulAuthentication(HttpServletRequest request, UserDetails user) {
		//key：作用是比较记住我认证对象是否是通过当前系统创建的
		//authoritiesMapper: 是一个权限映射器
		RememberMeAuthenticationToken auth = new RememberMeAuthenticationToken(this.key, user,
				this.authoritiesMapper.mapAuthorities(user.getAuthorities()));
		//构建详细信息
		auth.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return auth;
	}

	/**
	 * 解码记住我令牌并使用 “:” 分隔符将其拆分为一组令牌字符串
	 * @param cookieValue 记住我令牌，详情见encodeCookie()方法的介绍
	 * @return
	 * @throws InvalidCookieException
	 */
	protected String[] decodeCookie(String cookieValue) throws InvalidCookieException {
		//默认都是能够整除4的，不懂
		for (int j = 0; j < cookieValue.length() % 4; j++) {
			cookieValue = cookieValue + "=";
		}
		String cookieAsPlainText;
		try {
			//先尝试按照Base64解码出来
			cookieAsPlainText = new String(Base64.getDecoder().decode(cookieValue.getBytes()));
		}
		catch (IllegalArgumentException ex) {
			throw new InvalidCookieException("Cookie token was not Base64 encoded; value was '" + cookieValue + "'");
		}
		//按照Base64解码出来,并用:作为分隔符
		String[] tokens = StringUtils.delimitedListToStringArray(cookieAsPlainText, DELIMITER);
		for (int i = 0; i < tokens.length; i++) {
			try {
				//防止中文乱码
				tokens[i] = URLDecoder.decode(tokens[i], StandardCharsets.UTF_8.toString());
			}
			catch (UnsupportedEncodingException ex) {
				this.logger.error(ex.getMessage(), ex);
			}
		}
		return tokens;
	}

	/**
	 * 记住我令牌的加密
	 * @param cookieTokens 是用户名+过期时间戳+签名组成的数组
	 *                     签名又是通过 用MD5将过期时间戳+用户名+密码+秘钥进行加密得到的
	 * @return
	 */
	protected String encodeCookie(String[] cookieTokens) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < cookieTokens.length; i++) {
			try {
				//是为了解决中文乱码的问题
				sb.append(URLEncoder.encode(cookieTokens[i], StandardCharsets.UTF_8.toString()));
			}
			catch (UnsupportedEncodingException ex) {
				this.logger.error(ex.getMessage(), ex);
			}
			//加上分隔符
			if (i < cookieTokens.length - 1) {
				sb.append(DELIMITER);
			}
		}
		String value = sb.toString();
		//再进行Base64加密
		sb = new StringBuilder(new String(Base64.getEncoder().encode(value.getBytes())));
		while (sb.charAt(sb.length() - 1) == '=') {
			sb.deleteCharAt(sb.length() - 1);
		}
		return sb.toString();
	}

	@Override
	public final void loginFail(HttpServletRequest request, HttpServletResponse response) {
		this.logger.debug("Interactive login attempt was unsuccessful.");
		cancelCookie(request, response);
		onLoginFail(request, response);
	}

	protected void onLoginFail(HttpServletRequest request, HttpServletResponse response) {
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>
	 * Examines the incoming request and checks for the presence of the configured
	 * "remember me" parameter. If it's present, or if <tt>alwaysRemember</tt> is set to
	 * true, calls <tt>onLoginSucces</tt>.
	 * </p>
	 */
	@Override
	public final void loginSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication successfulAuthentication) {
		// 是否不开启记住我机制
		if (!rememberMeRequested(request, this.parameter)) {
			this.logger.debug("Remember-me login not requested.");
			return;
		}
		// 创建记住我令牌
		onLoginSuccess(request, response, successfulAuthentication);
	}

	/**
	 * Called from loginSuccess when a remember-me login has been requested. Typically
	 * implemented by subclasses to set a remember-me cookie and potentially store a
	 * record of it if the implementation requires this.
	 */
	protected abstract void onLoginSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication successfulAuthentication);

	/**
	 * 是否开启记住我机制
	 * <p>The default is to return true if <tt>alwaysRemember</tt> is set or the configured parameter
	 * name has been included in the request and is set to the value "true".
	 * @param request the request submitted from an interactive login, which may include
	 * additional information indicating that a persistent login is desired.
	 * @param parameter the configured remember-me parameter name.
	 * @return true if the request includes information indicating that a persistent login
	 * has been requested.
	 */
	protected boolean rememberMeRequested(HttpServletRequest request, String parameter) {
		// 服务端：是否一直需要携带记住我令牌
		if (this.alwaysRemember) {
			return true;
		}
		// 客户端：通过参数值来判断是否需要携带记住我令牌
		String paramValue = request.getParameter(parameter);
		if (paramValue != null) {
			if (paramValue.equalsIgnoreCase("true") || paramValue.equalsIgnoreCase("on")
					|| paramValue.equalsIgnoreCase("yes") || paramValue.equals("1")) {
				return true;
			}
		}
		this.logger.debug(
				LogMessage.format("Did not send remember-me cookie (principal did not set parameter '%s')", parameter));
		return false;
	}

	/**
	 * 交由子类去将记住我令牌转换为用户对象
	 * @param cookieTokens the decoded and tokenized cookie value
	 * @param request the request
	 * @param response the response, to allow the cookie to be modified if required.
	 * @return the UserDetails for the corresponding user account if the cookie was
	 * validated successfully.
	 * @throws RememberMeAuthenticationException if the cookie is invalid or the login is
	 * invalid for some other reason.
	 * @throws UsernameNotFoundException if the user account corresponding to the login
	 * cookie couldn't be found (for example if the user has been removed from the
	 * system).
	 */
	protected abstract UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request,
			HttpServletResponse response) throws RememberMeAuthenticationException, UsernameNotFoundException;

	/**
	 * 将生存时间设置为0，以禁用记住我认证
	 */
	protected void cancelCookie(HttpServletRequest request, HttpServletResponse response) {
		this.logger.debug("Cancelling cookie");
		Cookie cookie = new Cookie(this.cookieName, null);
		cookie.setMaxAge(0);
		cookie.setPath(getCookiePath(request));
		if (this.cookieDomain != null) {
			cookie.setDomain(this.cookieDomain);
		}
		cookie.setSecure((this.useSecureCookie != null) ? this.useSecureCookie : request.isSecure());
		response.addCookie(cookie);
	}

	/**
	 * 将Cookie设置到响应中
	 * @param tokens 新Cookie的值
	 * @param maxAge 有效时间
	 * @param request
	 * @param response
	 */
	protected void setCookie(String[] tokens, int maxAge, HttpServletRequest request, HttpServletResponse response) {
		//得到最终的记住我令牌
		String cookieValue = encodeCookie(tokens);
		Cookie cookie = new Cookie(this.cookieName, cookieValue);
		cookie.setMaxAge(maxAge);
		cookie.setPath(getCookiePath(request));
		if (this.cookieDomain != null) {
			cookie.setDomain(this.cookieDomain);
		}
		if (maxAge < 1) {
			cookie.setVersion(1);
		}
		cookie.setSecure((this.useSecureCookie != null) ? this.useSecureCookie : request.isSecure());
		//设置无法访问Cookie
		cookie.setHttpOnly(true);
		response.addCookie(cookie);
	}

	private String getCookiePath(HttpServletRequest request) {
		String contextPath = request.getContextPath();
		return (contextPath.length() > 0) ? contextPath : "/";
	}

	/**
	 * Implementation of {@code LogoutHandler}. Default behaviour is to call
	 * {@code cancelCookie()}.
	 */
	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		this.logger.debug(LogMessage
				.of(() -> "Logout of user " + ((authentication != null) ? authentication.getName() : "Unknown")));
		cancelCookie(request, response);
	}

	public void setCookieName(String cookieName) {
		Assert.hasLength(cookieName, "Cookie name cannot be empty or null");
		this.cookieName = cookieName;
	}

	public void setCookieDomain(String cookieDomain) {
		Assert.hasLength(cookieDomain, "Cookie domain cannot be empty or null");
		this.cookieDomain = cookieDomain;
	}

	protected String getCookieName() {
		return this.cookieName;
	}

	public void setAlwaysRemember(boolean alwaysRemember) {
		this.alwaysRemember = alwaysRemember;
	}

	/**
	 * Sets the name of the parameter which should be checked for to see if a remember-me
	 * has been requested during a login request. This should be the same name you assign
	 * to the checkbox in your login form.
	 * @param parameter the HTTP request parameter
	 */
	public void setParameter(String parameter) {
		Assert.hasText(parameter, "Parameter name cannot be empty or null");
		this.parameter = parameter;
	}

	public String getParameter() {
		return this.parameter;
	}

	protected UserDetailsService getUserDetailsService() {
		return this.userDetailsService;
	}

	public String getKey() {
		return this.key;
	}

	public void setTokenValiditySeconds(int tokenValiditySeconds) {
		this.tokenValiditySeconds = tokenValiditySeconds;
	}

	protected int getTokenValiditySeconds() {
		return this.tokenValiditySeconds;
	}

	/**
	 * Whether the cookie should be flagged as secure or not. Secure cookies can only be
	 * sent over an HTTPS connection and thus cannot be accidentally submitted over HTTP
	 * where they could be intercepted.
	 * <p>
	 * By default the cookie will be secure if the request is secure. If you only want to
	 * use remember-me over HTTPS (recommended) you should set this property to
	 * {@code true}.
	 * @param useSecureCookie set to {@code true} to always user secure cookies,
	 * {@code false} to disable their use.
	 */
	public void setUseSecureCookie(boolean useSecureCookie) {
		this.useSecureCookie = useSecureCookie;
	}

	protected AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
		return this.authenticationDetailsSource;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	/**
	 * Sets the strategy to be used to validate the {@code UserDetails} object obtained
	 * for the user when processing a remember-me cookie to automatically log in a user.
	 * @param userDetailsChecker the strategy which will be passed the user object to
	 * allow it to be rejected if account should not be allowed to authenticate (if it is
	 * locked, for example). Defaults to a {@code AccountStatusUserDetailsChecker}
	 * instance.
	 *
	 */
	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	/**
	 * @since 5.5
	 */
	@Override
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

}

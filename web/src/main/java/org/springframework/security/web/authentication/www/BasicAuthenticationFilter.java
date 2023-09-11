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

package org.springframework.security.web.authentication.www;

import java.io.IOException;
import java.nio.charset.Charset;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 基本认证过滤器
 * <p>
 * In summary, this filter is responsible for processing any request that has a HTTP
 * request header of <code>Authorization</code> with an authentication scheme of
 * <code>Basic</code> and a Base64-encoded <code>username:password</code> token. For
 * example, to authenticate user "Aladdin" with password "open sesame" the following
 * header would be presented:
 *
 * <pre>
 *
 * Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
 * </pre>
 *
 * <p>
 * This filter can be used to provide BASIC authentication services to both remoting
 * protocol clients (such as Hessian and SOAP) as well as standard user agents (such as
 * Internet Explorer and Netscape).
 * <p>
 * If authentication is successful, the resulting {@link Authentication} object will be
 * placed into the <code>SecurityContextHolder</code>.
 *
 * <p>
 * If authentication fails and <code>ignoreFailure</code> is <code>false</code> (the
 * default), an {@link AuthenticationEntryPoint} implementation is called (unless the
 * <tt>ignoreFailure</tt> property is set to <tt>true</tt>). Usually this should be
 * {@link BasicAuthenticationEntryPoint}, which will prompt the user to authenticate again
 * via BASIC authentication.
 *
 * <p>
 * Basic authentication is an attractive protocol because it is simple and widely
 * deployed. However, it still transmits a password in clear text and as such is
 * undesirable in many situations. Digest authentication is also provided by Spring
 * Security and should be used instead of Basic authentication wherever possible. See
 * {@link org.springframework.security.web.authentication.www.DigestAuthenticationFilter}.
 * <p>
 * Note that if a {@link RememberMeServices} is set, this filter will automatically send
 * back remember-me details to the client. Therefore, subsequent requests will not need to
 * present a BASIC authentication header as they will be authenticated using the
 * remember-me mechanism.
 *
 * @author Ben Alex
 */
public class BasicAuthenticationFilter extends OncePerRequestFilter {

	/**
	 * 基本认证出现问题时候，执行的身份认证入口点
	 */
	private AuthenticationEntryPoint authenticationEntryPoint;

	/**
	 * 局部认证管理器
	 */
	private AuthenticationManager authenticationManager;

	/**
	 * 记住我服务
	 */
	private RememberMeServices rememberMeServices = new NullRememberMeServices();

	/**
	 * 是否忽略依赖，让其执行下一个过滤器
	 */
	private boolean ignoreFailure = false;

	/**
	 * 本来应该是解密Basic64用到的编码格式，但是解密的时候直接用UTF-8，而没有使用这个，get方法也没有调用的地方
	 */
	private String credentialsCharset = "UTF-8";

	/**
	 * 认证对象转换器
	 */
	private BasicAuthenticationConverter authenticationConverter = new BasicAuthenticationConverter();

	/**
	 * Creates an instance which will authenticate against the supplied
	 * {@code AuthenticationManager} and which will ignore failed authentication attempts,
	 * allowing the request to proceed down the filter chain.
	 * @param authenticationManager the bean to submit authentication requests to
	 */
	public BasicAuthenticationFilter(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
		this.ignoreFailure = true;
	}

	/**
	 * Creates an instance which will authenticate against the supplied
	 * {@code AuthenticationManager} and use the supplied {@code AuthenticationEntryPoint}
	 * to handle authentication failures.
	 * @param authenticationManager the bean to submit authentication requests to
	 * @param authenticationEntryPoint will be invoked when authentication fails.
	 * Typically an instance of {@link BasicAuthenticationEntryPoint}.
	 */
	public BasicAuthenticationFilter(AuthenticationManager authenticationManager,
			AuthenticationEntryPoint authenticationEntryPoint) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		this.authenticationManager = authenticationManager;
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.authenticationManager, "An AuthenticationManager is required");
		if (!isIgnoreFailure()) {
			Assert.notNull(this.authenticationEntryPoint, "An AuthenticationEntryPoint is required");
		}
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		try {
			//通过解析request中的某些参数转为认证对象
			UsernamePasswordAuthenticationToken authRequest = this.authenticationConverter.convert(request);
			if (authRequest == null) {
				this.logger.trace("Did not process authentication request since failed to find "
						+ "username and password in Basic Authorization header");
				chain.doFilter(request, response);
				return;
			}
			String username = authRequest.getName();
			this.logger.trace(LogMessage.format("Found username '%s' in Basic Authorization header", username));
			//确定是否需要认证
			if (authenticationIsRequired(username)) {
				//调用认证管理器进行认证
				Authentication authResult = this.authenticationManager.authenticate(authRequest);

				//重新设置线程级别的安全上下文
				SecurityContext context = SecurityContextHolder.createEmptyContext();
				context.setAuthentication(authResult);
				SecurityContextHolder.setContext(context);
				if (this.logger.isDebugEnabled()) {
					this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
				}

				//添加记住我令牌
				this.rememberMeServices.loginSuccess(request, response, authResult);

				//执行认证成功后的操作
				onSuccessfulAuthentication(request, response, authResult);
			}
		}
		catch (AuthenticationException ex) {
			//先清空线程级别安全上下文
			SecurityContextHolder.clearContext();
			this.logger.debug("Failed to process authentication request", ex);

			//删除记住我令牌
			this.rememberMeServices.loginFail(request, response);

			onUnsuccessfulAuthentication(request, response, ex);

			//是否需要跳过异常
			if (this.ignoreFailure) {
				chain.doFilter(request, response);
			}
			else {
				this.authenticationEntryPoint.commence(request, response, ex);
			}
			return;
		}

		chain.doFilter(request, response);
	}

	/**
	 * 确定是否需要认证
	 * @param username
	 * @return
	 */
	private boolean authenticationIsRequired(String username) {
		// 只有在用户名不匹配线程级别安全上下文中的用户名，或者用户未经过认证时才重新进行认证
		Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
		if (existingAuth == null || !existingAuth.isAuthenticated()) {
			return true;
		}
		// 当是用户用户名和密码进行认证的，且用户名不同的时候，进行认证
		if (existingAuth instanceof UsernamePasswordAuthenticationToken && !existingAuth.getName().equals(username)) {
			return true;
		}

		// 处理匿名认证对象(AnonymousAuthenticationToken)已经存在的异常情况
		// 这种情况不应该经常发生，因为BasicProcessingFilter在过滤器链中比AnonymousAuthenticationFilter更早
		// 尽管如此，同时出现AnonymousAuthenticationToken和基本认证，应该表明需要使用BASIC协议进行重新身份认证
		// 这种行为也与表单认证和摘要认证一致，如果检测到各自的报头，它们都强制重新进行身份认证(并在此过程中替换/任何现有的AnonymousAuthenticationToken)
		return (existingAuth instanceof AnonymousAuthenticationToken);
	}

	protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			Authentication authResult) throws IOException {
	}

	protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException {
	}

	protected AuthenticationEntryPoint getAuthenticationEntryPoint() {
		return this.authenticationEntryPoint;
	}

	protected AuthenticationManager getAuthenticationManager() {
		return this.authenticationManager;
	}

	protected boolean isIgnoreFailure() {
		return this.ignoreFailure;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationConverter.setAuthenticationDetailsSource(authenticationDetailsSource);
	}

	public void setRememberMeServices(RememberMeServices rememberMeServices) {
		Assert.notNull(rememberMeServices, "rememberMeServices cannot be null");
		this.rememberMeServices = rememberMeServices;
	}

	public void setCredentialsCharset(String credentialsCharset) {
		Assert.hasText(credentialsCharset, "credentialsCharset cannot be null or empty");
		this.credentialsCharset = credentialsCharset;
		this.authenticationConverter.setCredentialsCharset(Charset.forName(credentialsCharset));
	}

	protected String getCredentialsCharset(HttpServletRequest httpRequest) {
		return this.credentialsCharset;
	}

}

/*
 * Copyright 2004, 2005, 2006, 2009 Acegi Technology Pty Limited
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
import java.util.Base64;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

/**
 * 摘要认证的过滤器
 * Processes a HTTP request's Digest authorization headers, putting the result into the
 * <code>SecurityContextHolder</code>.
 * <p>
 * For a detailed background on what this filter is designed to process, refer to
 * <a href="https://www.ietf.org/rfc/rfc2617.txt">RFC 2617</a> (which superseded RFC 2069,
 * although this filter support clients that implement either RFC 2617 or RFC 2069).
 * <p>
 * This filter can be used to provide Digest authentication services to both remoting
 * protocol clients (such as Hessian and SOAP) as well as standard user agents (such as
 * Internet Explorer and FireFox).
 * <p>
 * This Digest implementation has been designed to avoid needing to store session state
 * between invocations. All session management information is stored in the "nonce" that
 * is sent to the client by the {@link DigestAuthenticationEntryPoint}.
 * <p>
 * If authentication is successful, the resulting
 * {@link org.springframework.security.core.Authentication Authentication} object will be
 * placed into the <code>SecurityContextHolder</code>.
 * <p>
 * If authentication fails, an
 * {@link org.springframework.security.web.AuthenticationEntryPoint
 * AuthenticationEntryPoint} implementation is called. This must always be
 * {@link DigestAuthenticationEntryPoint}, which will prompt the user to authenticate
 * again via Digest authentication.
 * <p>
 * Note there are limitations to Digest authentication, although it is a more
 * comprehensive and secure solution than Basic authentication. Please see RFC 2617
 * section 4 for a full discussion on the advantages of Digest authentication over Basic
 * authentication, including commentary on the limitations that it still imposes.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @since 1.0.0
 */
public class DigestAuthenticationFilter extends GenericFilterBean implements MessageSourceAware {

	private static final Log logger = LogFactory.getLog(DigestAuthenticationFilter.class);

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	/**
	 * 身份认证入口点，此处的是在验证摘要数据失败的时候执行
	 */
	private DigestAuthenticationEntryPoint authenticationEntryPoint;

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private UserCache userCache = new NullUserCache();

	private UserDetailsService userDetailsService;

	/**
	 * 密码是否已经加密
	 */
	private boolean passwordAlreadyEncoded = false;

	/**
	 * 是否在创建认证对象的时候，填充权限
	 */
	private boolean createAuthenticatedToken = false;

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.userDetailsService, "A UserDetailsService is required");
		Assert.notNull(this.authenticationEntryPoint, "A DigestAuthenticationEntryPoint is required");
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String header = request.getHeader("Authorization");
		if (header == null || !header.startsWith("Digest ")) {
			chain.doFilter(request, response);
			return;
		}
		logger.debug(LogMessage.format("Digest Authorization header received from user agent: %s", header));
		DigestData digestAuth = new DigestData(header);
		try {
			//检查摘要数据的合法性
			digestAuth.validateAndDecode(this.authenticationEntryPoint.getKey(),
					this.authenticationEntryPoint.getRealmName());
		}
		catch (BadCredentialsException ex) {
			fail(request, response, ex);
			return;
		}

		//是否使用缓存中的用户
		boolean cacheWasUsed = true;

		UserDetails user = this.userCache.getUserFromCache(digestAuth.getUsername());
		String serverDigestMd5;
		try {
			if (user == null) {
				cacheWasUsed = false;
				user = this.userDetailsService.loadUserByUsername(digestAuth.getUsername());
				if (user == null) {
					throw new AuthenticationServiceException(
							"AuthenticationDao returned null, which is an interface contract violation");
				}
				this.userCache.putUserInCache(user);
			}

			// 计算摘要值
			serverDigestMd5 = digestAuth.calculateServerDigest(user.getPassword(), request.getMethod());
			// If digest is incorrect, try refreshing from backend and recomputing
			if (!serverDigestMd5.equals(digestAuth.getResponse()) && cacheWasUsed) {
				logger.debug("Digest comparison failure; trying to refresh user from DAO in case password had changed");
				// 如果是缓存中的密码参与了计算摘要值的计算过程
				// 那么可能是密码更新了，导致执行到这的，所以获取最新的密码
				// 再重新计算摘要值
				user = this.userDetailsService.loadUserByUsername(digestAuth.getUsername());
				this.userCache.putUserInCache(user);
				serverDigestMd5 = digestAuth.calculateServerDigest(user.getPassword(), request.getMethod());
			}
		}
		catch (UsernameNotFoundException ex) {
			String message = this.messages.getMessage("DigestAuthenticationFilter.usernameNotFound",
					new Object[] { digestAuth.getUsername() }, "Username {0} not found");
			fail(request, response, new BadCredentialsException(message));
			return;
		}

		// 如果摘要值仍然不正确，则执行失败策略
		if (!serverDigestMd5.equals(digestAuth.getResponse())) {
			logger.debug(LogMessage.format(
					"Expected response: '%s' but received: '%s'; is AuthenticationDao returning clear text passwords?",
					serverDigestMd5, digestAuth.getResponse()));
			String message = this.messages.getMessage("DigestAuthenticationFilter.incorrectResponse",
					"Incorrect response");
			//失败策略
			fail(request, response, new BadCredentialsException(message));
			return;
		}
		// 走这一步，摘要已经是有效的
		// 但是可能会存在过期的情况
		if (digestAuth.isNonceExpired()) {
			String message = this.messages.getMessage("DigestAuthenticationFilter.nonceExpired",
					"Nonce has expired/timed out");
			fail(request, response, new NonceExpiredException(message));
			return;
		}
		logger.debug(LogMessage.format("Authentication success for user: '%s' with response: '%s'",
				digestAuth.getUsername(), digestAuth.getResponse()));


		//认证成功，创建认证对象
		Authentication authentication = createSuccessfulAuthentication(request, user);

		//创建线程级别的安全上下文
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		SecurityContextHolder.setContext(context);

		chain.doFilter(request, response);
	}

	/**
	 * 认证成功，创建认证对象
	 * @param request
	 * @param user
	 * @return
	 */
	private Authentication createSuccessfulAuthentication(HttpServletRequest request, UserDetails user) {
		UsernamePasswordAuthenticationToken authRequest = getAuthRequest(user);
		authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return authRequest;
	}

	private UsernamePasswordAuthenticationToken getAuthRequest(UserDetails user) {
		if (this.createAuthenticatedToken) {
			return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
		}
		return new UsernamePasswordAuthenticationToken(user, user.getPassword());
	}

	/**
	 * 摘要认证失败执行的方法
	 * @param request
	 * @param response
	 * @param failed
	 * @throws IOException
	 * @throws ServletException
	 */
	private void fail(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
			throws IOException, ServletException {
		//清空线程级别的安全上下文
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		SecurityContextHolder.setContext(context);
		logger.debug(failed);
		//通常是跳转到登录页
		this.authenticationEntryPoint.commence(request, response, failed);
	}

	protected final DigestAuthenticationEntryPoint getAuthenticationEntryPoint() {
		return this.authenticationEntryPoint;
	}

	public UserCache getUserCache() {
		return this.userCache;
	}

	public UserDetailsService getUserDetailsService() {
		return this.userDetailsService;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public void setAuthenticationEntryPoint(DigestAuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	public void setPasswordAlreadyEncoded(boolean passwordAlreadyEncoded) {
		this.passwordAlreadyEncoded = passwordAlreadyEncoded;
	}

	public void setUserCache(UserCache userCache) {
		this.userCache = userCache;
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	/**
	 * If you set this property, the Authentication object, which is created after the
	 * successful digest authentication will be marked as <b>authenticated</b> and filled
	 * with the authorities loaded by the UserDetailsService. It therefore will not be
	 * re-authenticated by your AuthenticationProvider. This means, that only the password
	 * of the user is checked, but not the flags like isEnabled() or
	 * isAccountNonExpired(). You will save some time by enabling this flag, as otherwise
	 * your UserDetailsService will be called twice. A more secure option would be to
	 * introduce a cache around your UserDetailsService, but if you don't use these flags,
	 * you can also safely enable this option.
	 * @param createAuthenticatedToken default is false
	 */
	public void setCreateAuthenticatedToken(boolean createAuthenticatedToken) {
		this.createAuthenticatedToken = createAuthenticatedToken;
	}

	/**
	 * 摘要数据的实体
	 */
	private class DigestData {

		/**
		 * 登录用户名
		 */
		private final String username;

		/**
		 * 认证域
		 */
		private final String realm;

		/**
		 * 由服务器生成的随机字符串，包含过期时间和密钥
		 */
		private final String nonce;

		/**
		 * 请求的Url
		 */
		private final String uri;

		/**
		 * 客户端根据算法算出的摘要值，取决于qop
		 */
		private final String response;

		/**
		 * 客户端根据此参数指定摘要算法
		 * <ul>
		 *     <li>
		 *         若是auth，则只进行身份验证，也是默认值
		 *     </li>
		 *     <li>
		 *         若是auth-int，则还需要校验内容完整值
		 *     </li>
		 * </ul>
		 */
		private final String qop;

		/**
		 * 请求的次数，用于计数，以防止重放攻击
		 */
		private final String nc;

		/**
		 * 客户端给服务器的随机字符串
		 */
		private final String cnonce;

		/**
		 * 完整的摘要数据
		 */
		private final String section212response;

		/**
		 * 解密出来的过期时间
		 */
		private long nonceExpiryTime;

		DigestData(String header) {
			this.section212response = header.substring(7);
			String[] headerEntries = DigestAuthUtils.splitIgnoringQuotes(this.section212response, ',');
			Map<String, String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");
			this.username = headerMap.get("username");
			this.realm = headerMap.get("realm");
			this.nonce = headerMap.get("nonce");
			this.uri = headerMap.get("uri");
			this.response = headerMap.get("response");
			this.qop = headerMap.get("qop"); // RFC 2617 extension
			this.nc = headerMap.get("nc"); // RFC 2617 extension
			this.cnonce = headerMap.get("cnonce"); // RFC 2617 extension
			logger.debug(
					LogMessage.format("Extracted username: '%s'; realm: '%s'; nonce: '%s'; uri: '%s'; response: '%s'",
							this.username, this.realm, this.nonce, this.uri, this.response));
		}

		/**
		 * 检查摘要数据的合法性
		 * @param entryPointKey
		 * @param expectedRealm
		 * @throws BadCredentialsException
		 */
		void validateAndDecode(String entryPointKey, String expectedRealm) throws BadCredentialsException {
			//检查所有必需参数都已经有值
			if ((this.username == null) || (this.realm == null) || (this.nonce == null) || (this.uri == null)
					|| (this.response == null)) {
				throw new BadCredentialsException(DigestAuthenticationFilter.this.messages.getMessage(
						"DigestAuthenticationFilter.missingMandatory", new Object[] { this.section212response },
						"Missing mandatory digest value; received header {0}"));
			}
			//继续检查参数
			if ("auth".equals(this.qop)) {
				if ((this.nc == null) || (this.cnonce == null)) {
					logger.debug(LogMessage.format("extracted nc: '%s'; cnonce: '%s'", this.nc, this.cnonce));
					throw new BadCredentialsException(DigestAuthenticationFilter.this.messages.getMessage(
							"DigestAuthenticationFilter.missingAuth", new Object[] { this.section212response },
							"Missing mandatory digest value; received header {0}"));
				}
			}
			//检查保护域是否是我们的
			if (!expectedRealm.equals(this.realm)) {
				throw new BadCredentialsException(DigestAuthenticationFilter.this.messages.getMessage(
						"DigestAuthenticationFilter.incorrectRealm", new Object[] { this.realm, expectedRealm },
						"Response realm name '{0}' does not match system realm name of '{1}'"));
			}
			//检查摘要数据是否能够通过Base64解密
			final byte[] nonceBytes;
			try {
				nonceBytes = Base64.getDecoder().decode(this.nonce.getBytes());
			}
			catch (IllegalArgumentException ex) {
				throw new BadCredentialsException(
						DigestAuthenticationFilter.this.messages.getMessage("DigestAuthenticationFilter.nonceEncoding",
								new Object[] { this.nonce }, "Nonce is not encoded in Base64; received nonce {0}"));
			}
			// 解密nonce，nonce格式为: base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
			String nonceAsPlainText = new String(nonceBytes);
			String[] nonceTokens = StringUtils.delimitedListToStringArray(nonceAsPlainText, ":");

			//nonce中只会包含两个东西
			if (nonceTokens.length != 2) {
				throw new BadCredentialsException(DigestAuthenticationFilter.this.messages.getMessage(
						"DigestAuthenticationFilter.nonceNotTwoTokens", new Object[] { nonceAsPlainText },
						"Nonce should have yielded two tokens but was {0}"));
			}

			//从nonce中提取过期时间
			try {
				this.nonceExpiryTime = new Long(nonceTokens[0]);
			}
			catch (NumberFormatException nfe) {
				throw new BadCredentialsException(DigestAuthenticationFilter.this.messages.getMessage(
						"DigestAuthenticationFilter.nonceNotNumeric", new Object[] { nonceAsPlainText },
						"Nonce token should have yielded a numeric first token, but was {0}"));
			}

			//用过期时间+密钥重新加密
			//判断是否是自己创建的
			String expectedNonceSignature = DigestAuthUtils.md5Hex(this.nonceExpiryTime + ":" + entryPointKey);
			if (!expectedNonceSignature.equals(nonceTokens[1])) {
				throw new BadCredentialsException(DigestAuthenticationFilter.this.messages.getMessage(
						"DigestAuthenticationFilter.nonceCompromised", new Object[] { nonceAsPlainText },
						"Nonce token compromised {0}"));
			}
		}

		/**
		 * 计算摘要值
		 * @param password
		 * @param httpMethod
		 * @return
		 */
		String calculateServerDigest(String password, String httpMethod) {
			// Compute the expected response-digest (will be in hex form). Don't catch
			// IllegalArgumentException (already checked validity)
			return DigestAuthUtils.generateDigest(DigestAuthenticationFilter.this.passwordAlreadyEncoded, this.username,
					this.realm, password, httpMethod, this.uri, this.qop, this.nonce, this.nc, this.cnonce);
		}

		boolean isNonceExpired() {
			long now = System.currentTimeMillis();
			return this.nonceExpiryTime < now;
		}

		String getUsername() {
			return this.username;
		}

		String getResponse() {
			return this.response;
		}

	}

}

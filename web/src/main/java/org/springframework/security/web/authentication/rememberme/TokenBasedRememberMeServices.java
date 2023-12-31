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

package org.springframework.security.web.authentication.rememberme;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Identifies previously remembered users by a Base-64 encoded cookie.
 *
 * <p>
 * This implementation does not rely on an external database, so is attractive for simple
 * applications. The cookie will be valid for a specific period from the date of the last
 * {@link #loginSuccess(HttpServletRequest, HttpServletResponse, Authentication)}. As per
 * the interface contract, this method will only be called when the principal completes a
 * successful interactive authentication. As such the time period commences from the last
 * authentication attempt where they furnished credentials - not the time period they last
 * logged in via remember-me. The implementation will only send a remember-me token if the
 * parameter defined by {@link #setParameter(String)} is present.
 * <p>
 * An {@link org.springframework.security.core.userdetails.UserDetailsService} is required
 * by this implementation, so that it can construct a valid <code>Authentication</code>
 * from the returned {@link org.springframework.security.core.userdetails.UserDetails}.
 * This is also necessary so that the user's password is available and can be checked as
 * part of the encoded cookie.
 * <p>
 * The cookie encoded by this implementation adopts the following form:
 *
 * <pre>
 * username + &quot;:&quot; + expiryTime + &quot;:&quot;
 * 		+ Md5Hex(username + &quot;:&quot; + expiryTime + &quot;:&quot; + password + &quot;:&quot; + key)
 * </pre>
 *
 * <p>
 * As such, if the user changes their password, any remember-me token will be invalidated.
 * Equally, the system administrator may invalidate every remember-me token on issue by
 * changing the key. This provides some reasonable approaches to recovering from a
 * remember-me token being left on a public machine (e.g. kiosk system, Internet cafe
 * etc). Most importantly, at no time is the user's password ever sent to the user agent,
 * providing an important security safeguard. Unfortunately the username is necessary in
 * this implementation (as we do not want to rely on a database for remember-me services).
 * High security applications should be aware of this occasionally undesired disclosure of
 * a valid username.
 * <p>
 * This is a basic remember-me implementation which is suitable for many applications.
 * However, we recommend a database-based implementation if you require a more secure
 * remember-me approach (see {@link PersistentTokenBasedRememberMeServices}).
 * <p>
 * By default the tokens will be valid for 14 days from the last successful authentication
 * attempt. This can be changed using {@link #setTokenValiditySeconds(int)}. If this value
 * is less than zero, the <tt>expiryTime</tt> will remain at 14 days, but the negative
 * value will be used for the <tt>maxAge</tt> property of the cookie, meaning that it will
 * not be stored when the browser is closed.
 *
 * @author Ben Alex
 */
public class TokenBasedRememberMeServices extends AbstractRememberMeServices {

	public TokenBasedRememberMeServices(String key, UserDetailsService userDetailsService) {
		super(key, userDetailsService);
	}

	/**
	 * 将记住我令牌转换为用户对象
	 * @param cookieTokens 记住我令牌 <p>是用户+过期时间戳+签名组成的数组</p><p>
	 *                     签名又是通过 用MD5将过期时间戳+用户名+密码+秘钥进行加密得到的
	 * </p>
	 * @param request the request
	 * @param response the response, to allow the cookie to be modified if required.
	 * @return
	 */
	@Override
	protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request,
			HttpServletResponse response) {
		//使用当前记住我服务只会生成长度为3的记住我令牌
		if (cookieTokens.length != 3) {
			throw new InvalidCookieException(
					"Cookie token did not contain 3" + " tokens, but contained '" + Arrays.asList(cookieTokens) + "'");
		}
		//获得过期时间
		long tokenExpiryTime = getTokenExpiryTime(cookieTokens);
		//判断记住我令牌是否已经过期
		if (isTokenExpired(tokenExpiryTime)) {
			throw new InvalidCookieException("Cookie token[1] has expired (expired on '" + new Date(tokenExpiryTime)
					+ "'; current time is '" + new Date() + "')");
		}

		//通过用户名加载UserDetails
		UserDetails userDetails = getUserDetailsService().loadUserByUsername(cookieTokens[0]);
		Assert.notNull(userDetails, () -> "UserDetailsService " + getUserDetailsService()
				+ " returned null for username " + cookieTokens[0] + ". " + "This is an interface contract violation");

		//以原有的固定的参数重新生成签名
		String expectedTokenSignature = makeTokenSignature(tokenExpiryTime, userDetails.getUsername(),
				userDetails.getPassword());
		//如果不一样，就抛出异常
		if (!equals(expectedTokenSignature, cookieTokens[2])) {
			throw new InvalidCookieException("Cookie token[2] contained signature '" + cookieTokens[2]
					+ "' but expected '" + expectedTokenSignature + "'");
		}
		return userDetails;
	}

	/**
	 * 获得过期时间
	 * @param cookieTokens
	 * @return
	 */
	private long getTokenExpiryTime(String[] cookieTokens) {
		try {
			return new Long(cookieTokens[1]);
		}
		catch (NumberFormatException nfe) {
			throw new InvalidCookieException(
					"Cookie token[1] did not contain a valid number (contained '" + cookieTokens[1] + "')");
		}
	}

	/**
	 * 生成签名，并通过MD5进行加密
	 */
	protected String makeTokenSignature(long tokenExpiryTime, String username, String password) {
		String data = username + ":" + tokenExpiryTime + ":" + password + ":" + getKey();
		try {
			MessageDigest digest = MessageDigest.getInstance("MD5");
			return new String(Hex.encode(digest.digest(data.getBytes())));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("No MD5 algorithm available!");
		}
	}

	/**
	 * 判断记住我令牌是否已经过期
	 * @param tokenExpiryTime
	 * @return
	 */
	protected boolean isTokenExpired(long tokenExpiryTime) {
		return tokenExpiryTime < System.currentTimeMillis();
	}

	/**
	 * 为认证成功的请求新增一个记住我令牌
	 * @param request
	 * @param response
	 * @param successfulAuthentication
	 */
	@Override
	public void onLoginSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication successfulAuthentication) {
		//获得用户名和密码
		String username = retrieveUserName(successfulAuthentication);
		String password = retrievePassword(successfulAuthentication);

		//如若无法找到用户名和密码就终止创建记住我令牌
		if (!StringUtils.hasLength(username)) {
			this.logger.debug("Unable to retrieve username");
			return;
		}
		if (!StringUtils.hasLength(password)) {
			//尝试通过用户详情服务获取密码
			UserDetails user = getUserDetailsService().loadUserByUsername(username);
			password = user.getPassword();
			if (!StringUtils.hasLength(password)) {
				this.logger.debug("Unable to obtain password for user: " + username);
				return;
			}
		}

		//获得记住我令牌有效时间
		int tokenLifetime = calculateLoginLifetime(request, successfulAuthentication);
		long expiryTime = System.currentTimeMillis();
		//过期时间 = 令牌有效时间 + 当前时间
		expiryTime += 1000L * ((tokenLifetime < 0) ? TWO_WEEKS_S : tokenLifetime);
		//生成签名
		String signatureValue = makeTokenSignature(expiryTime, username, password);
		//将记住我令牌添加到Cookie中
		setCookie(new String[] { username, Long.toString(expiryTime), signatureValue }, tokenLifetime, request,
				response);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(
					"Added remember-me cookie for user '" + username + "', expiry: '" + new Date(expiryTime) + "'");
		}
	}

	/**
	 * 返回记住我令牌有效时间
	 */
	protected int calculateLoginLifetime(HttpServletRequest request, Authentication authentication) {
		return getTokenValiditySeconds();
	}

	/**
	 * 获得用户名
	 * @param authentication
	 * @return
	 */
	protected String retrieveUserName(Authentication authentication) {
		//校验主要信息是否是一个UserDetails
		if (isInstanceOfUserDetails(authentication)) {
			return ((UserDetails) authentication.getPrincipal()).getUsername();
		}
		//其他情况Principal中就是用户名了
		return authentication.getPrincipal().toString();
	}

	protected String retrievePassword(Authentication authentication) {
		if (isInstanceOfUserDetails(authentication)) {
			return ((UserDetails) authentication.getPrincipal()).getPassword();
		}
		if (authentication.getCredentials() != null) {
			return authentication.getCredentials().toString();
		}
		return null;
	}

	/**
	 * 校验主要信息是否是一个UserDetails
	 * @param authentication
	 * @return
	 */
	private boolean isInstanceOfUserDetails(Authentication authentication) {
		return authentication.getPrincipal() instanceof UserDetails;
	}

	/**
	 * Constant time comparison to prevent against timing attacks.
	 */
	private static boolean equals(String expected, String actual) {
		byte[] expectedBytes = bytesUtf8(expected);
		byte[] actualBytes = bytesUtf8(actual);
		return MessageDigest.isEqual(expectedBytes, actualBytes);
	}

	private static byte[] bytesUtf8(String s) {
		return (s != null) ? Utf8.encode(s) : null;
	}

}

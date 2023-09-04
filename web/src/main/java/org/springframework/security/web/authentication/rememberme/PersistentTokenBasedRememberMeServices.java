/*
 * Copyright 2002-2017 the original author or authors.
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

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.util.Assert;

/**
 * 支持持久化的记住我服务
 */
public class PersistentTokenBasedRememberMeServices extends AbstractRememberMeServices {

	/**
	 * 持久化记住我令牌策略
	 */
	private PersistentTokenRepository tokenRepository = new InMemoryTokenRepositoryImpl();

	/**
	 * 生成Secure和Token值的
	 */
	private SecureRandom random;

	public static final int DEFAULT_SERIES_LENGTH = 16;

	public static final int DEFAULT_TOKEN_LENGTH = 16;

	private int seriesLength = DEFAULT_SERIES_LENGTH;

	private int tokenLength = DEFAULT_TOKEN_LENGTH;

	public PersistentTokenBasedRememberMeServices(String key, UserDetailsService userDetailsService,
			PersistentTokenRepository tokenRepository) {
		super(key, userDetailsService);
		this.random = new SecureRandom();
		this.tokenRepository = tokenRepository;
	}

	/**
	 * 解密记住我令牌
	 * <ul>
	 *     <li>
	 *         可以防止令牌泄露
	 *     </li>
	 *     <li>
	 *         会生成新的令牌
	 *     </li>
	 * </ul>
	 */
	@Override
	protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request,
			HttpServletResponse response) {
		//使用当前记住我服务只会生成长度为2的记住我令牌
		if (cookieTokens.length != 2) {
			throw new InvalidCookieException("Cookie token did not contain " + 2 + " tokens, but contained '"
					+ Arrays.asList(cookieTokens) + "'");
		}
		//生成记住我令牌的时候就已经固定了第一位是Series，第二位是Token
		String presentedSeries = cookieTokens[0];
		String presentedToken = cookieTokens[1];
		//先通过持久化策略获得 保存的持久化记住我令牌
		PersistentRememberMeToken token = this.tokenRepository.getTokenForSeries(presentedSeries);
		if (token == null) {
			//没有保存，不能使用此cookie进行身份认证
			throw new RememberMeAuthenticationException("No persistent token found for series id: " + presentedSeries);
		}
		//当token值不等的时候，说明此记住我令牌已经泄露了
		if (!presentedToken.equals(token.getTokenValue())) {
			//删除用此用户名登录的所有 持久化记住我令牌
			this.tokenRepository.removeUserTokens(token.getUsername());
			//抛出异常，这样用户就知道了记住我令牌已经泄露了
			throw new CookieTheftException(this.messages.getMessage(
					"PersistentTokenBasedRememberMeServices.cookieStolen",
					"Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack."));
		}
		//判断是否过期
		if (token.getDate().getTime() + getTokenValiditySeconds() * 1000L < System.currentTimeMillis()) {
			throw new RememberMeAuthenticationException("Remember-me login has expired");
		}


		this.logger.debug(LogMessage.format("Refreshing persistent login token for user '%s', series '%s'",
				token.getUsername(), token.getSeries()));

		//此记住我令牌是有效的，更新token值和时间
		PersistentRememberMeToken newToken = new PersistentRememberMeToken(token.getUsername(), token.getSeries(),
				generateTokenData(), new Date());
		try {
			//更新
			this.tokenRepository.updateToken(newToken.getSeries(), newToken.getTokenValue(), newToken.getDate());
			//添加新的记住我令牌
			addCookie(newToken, request, response);
		}
		catch (Exception ex) {
			this.logger.error("Failed to update token: ", ex);
			throw new RememberMeAuthenticationException("Autologin failed due to data access problem");
		}
		return getUserDetailsService().loadUserByUsername(token.getUsername());
	}

	/**
	 * 创建具有新的持久话记住我令牌
	 * 将数据存储在持久令牌存储库中，并将相应的cookie添加到响应中。
	 */
	@Override
	protected void onLoginSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication successfulAuthentication) {
		String username = successfulAuthentication.getName();
		this.logger.debug(LogMessage.format("Creating new persistent login for user %s", username));

		PersistentRememberMeToken persistentToken = new PersistentRememberMeToken(username, generateSeriesData(),
				generateTokenData(), new Date());
		try {
			//保存起来，一般情况是数据库
			this.tokenRepository.createNewToken(persistentToken);
			//添加记住我令牌到响应的Cookie中
			addCookie(persistentToken, request, response);
		}
		catch (Exception ex) {
			this.logger.error("Failed to save persistent token ", ex);
		}
	}

	/**
	 * 登出策略
	 * <ul>
	 *     <li>
	 *         这是因为登出的时候，需要删除保存的记录
	 *     </li>
	 * </ul>
	 * @param request
	 * @param response
	 * @param authentication
	 */
	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		super.logout(request, response, authentication);
		if (authentication != null) {
			this.tokenRepository.removeUserTokens(authentication.getName());
		}
	}

	/**
	 * 生成Series随机数
	 * @return
	 */
	protected String generateSeriesData() {
		byte[] newSeries = new byte[this.seriesLength];
		this.random.nextBytes(newSeries);
		return new String(Base64.getEncoder().encode(newSeries));
	}

	/**
	 * 生成Token随机数
	 * @return
	 */
	protected String generateTokenData() {
		byte[] newToken = new byte[this.tokenLength];
		this.random.nextBytes(newToken);
		return new String(Base64.getEncoder().encode(newToken));
	}

	/**
	 * 添加记住我令牌到添加到响应中
	 * @param token
	 * @param request
	 * @param response
	 */
	private void addCookie(PersistentRememberMeToken token, HttpServletRequest request, HttpServletResponse response) {
		// 可以看出此时的记住我令牌是由 Series + TokenValue
		setCookie(new String[] { token.getSeries(), token.getTokenValue() }, getTokenValiditySeconds(), request,
				response);
	}

	public void setSeriesLength(int seriesLength) {
		this.seriesLength = seriesLength;
	}

	public void setTokenLength(int tokenLength) {
		this.tokenLength = tokenLength;
	}

	@Override
	public void setTokenValiditySeconds(int tokenValiditySeconds) {
		Assert.isTrue(tokenValiditySeconds > 0, "tokenValiditySeconds must be positive for this implementation");
		super.setTokenValiditySeconds(tokenValiditySeconds);
	}

}

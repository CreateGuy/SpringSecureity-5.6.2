/*
 * Copyright 2002-2015 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import java.util.UUID;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.util.Assert;

/**
 * 记住我功能的配置类
 */
public final class RememberMeConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<RememberMeConfigurer<H>, H> {

	/**
	 * cookie中记住我参数的默认名称
	 */
	private static final String DEFAULT_REMEMBER_ME_NAME = "remember-me";

	/**
	 * 认证成功处理器
	 */
	private AuthenticationSuccessHandler authenticationSuccessHandler;

	/**
	 * 生成记住我参数的加密参数，以及通过认证器进行认证就只是比较这个key
	 */
	private String key;

	/**
	 * 记住我服务
	 */
	private RememberMeServices rememberMeServices;

	/**
	 * 登出处理器
	 */
	private LogoutHandler logoutHandler;

	/**
	 * 表单登录或者其他登录方式中：标记是否开启了记住我功能
	 */
	private String rememberMeParameter = DEFAULT_REMEMBER_ME_NAME;

	/**
	 * 记住我参数放在Cookie中的参数名称
	 */
	private String rememberMeCookieName = DEFAULT_REMEMBER_ME_NAME;

	/**
	 * 指定记住我参令牌可访问的域名
	 */
	private String rememberMeCookieDomain;

	/**
	 * 记住我令牌存储策略：使用持久化方式来保持记住我令牌
	 */
	private PersistentTokenRepository tokenRepository;

	/**
	 * 用户详情服务
	 */
	private UserDetailsService userDetailsService;

	/**
	 * 记住我令牌过期时间
	 */
	private Integer tokenValiditySeconds;

	/**
	 * 为true时必须通过https请求才能携带cookie中的信息
	 */
	private Boolean useSecureCookie;

	/**
	 * 是否需要携带记住我令牌
	 * <url>
	 *     <li>
	 *         true：都携带记住我令牌
	 *     </li>
	 *     <li>
	 *         false：看是否携带了记住我参数
	 *     </li>
	 * </url>
	 */
	private Boolean alwaysRemember;

	/**
	 * Creates a new instance
	 */
	public RememberMeConfigurer() {
	}

	/**
	 * Allows specifying how long (in seconds) a token is valid for
	 * @param tokenValiditySeconds
	 * @return {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices#setTokenValiditySeconds(int)
	 */
	public RememberMeConfigurer<H> tokenValiditySeconds(int tokenValiditySeconds) {
		this.tokenValiditySeconds = tokenValiditySeconds;
		return this;
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
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices#setUseSecureCookie(boolean)
	 */
	public RememberMeConfigurer<H> useSecureCookie(boolean useSecureCookie) {
		this.useSecureCookie = useSecureCookie;
		return this;
	}

	/**
	 * Specifies the {@link UserDetailsService} used to look up the {@link UserDetails}
	 * when a remember me token is valid. The default is to use the
	 * {@link UserDetailsService} found by invoking
	 * {@link HttpSecurity#getSharedObject(Class)} which is set when using
	 * {@link WebSecurityConfigurerAdapter#configure(AuthenticationManagerBuilder)}.
	 * Alternatively, one can populate {@link #rememberMeServices(RememberMeServices)}.
	 * @param userDetailsService the {@link UserDetailsService} to configure
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices
	 */
	public RememberMeConfigurer<H> userDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
		return this;
	}

	/**
	 * Specifies the {@link PersistentTokenRepository} to use. The default is to use
	 * {@link TokenBasedRememberMeServices} instead.
	 * @param tokenRepository the {@link PersistentTokenRepository} to use
	 * @return the {@link RememberMeConfigurer} for further customization
	 */
	public RememberMeConfigurer<H> tokenRepository(PersistentTokenRepository tokenRepository) {
		this.tokenRepository = tokenRepository;
		return this;
	}

	/**
	 * Sets the key to identify tokens created for remember me authentication. Default is
	 * a secure randomly generated key. If {@link #rememberMeServices(RememberMeServices)}
	 * is specified and is of type {@link AbstractRememberMeServices}, then the default is
	 * the key set in {@link AbstractRememberMeServices}.
	 * @param key the key to identify tokens created for remember me authentication
	 * @return the {@link RememberMeConfigurer} for further customization
	 */
	public RememberMeConfigurer<H> key(String key) {
		this.key = key;
		return this;
	}

	/**
	 * The HTTP parameter used to indicate to remember the user at time of login.
	 * @param rememberMeParameter the HTTP parameter used to indicate to remember the user
	 * @return the {@link RememberMeConfigurer} for further customization
	 */
	public RememberMeConfigurer<H> rememberMeParameter(String rememberMeParameter) {
		this.rememberMeParameter = rememberMeParameter;
		return this;
	}

	/**
	 * The name of cookie which store the token for remember me authentication. Defaults
	 * to 'remember-me'.
	 * @param rememberMeCookieName the name of cookie which store the token for remember
	 * me authentication
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @since 4.0.1
	 */
	public RememberMeConfigurer<H> rememberMeCookieName(String rememberMeCookieName) {
		this.rememberMeCookieName = rememberMeCookieName;
		return this;
	}

	/**
	 * The domain name within which the remember me cookie is visible.
	 * @param rememberMeCookieDomain the domain name within which the remember me cookie
	 * is visible.
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @since 4.1.0
	 */
	public RememberMeConfigurer<H> rememberMeCookieDomain(String rememberMeCookieDomain) {
		this.rememberMeCookieDomain = rememberMeCookieDomain;
		return this;
	}

	/**
	 * Allows control over the destination a remembered user is sent to when they are
	 * successfully authenticated. By default, the filter will just allow the current
	 * request to proceed, but if an {@code AuthenticationSuccessHandler} is set, it will
	 * be invoked and the {@code doFilter()} method will return immediately, thus allowing
	 * the application to redirect the user to a specific URL, regardless of what the
	 * original request was for.
	 * @param authenticationSuccessHandler the strategy to invoke immediately before
	 * returning from {@code doFilter()}.
	 * @return {@link RememberMeConfigurer} for further customization
	 * @see RememberMeAuthenticationFilter#setAuthenticationSuccessHandler(AuthenticationSuccessHandler)
	 */
	public RememberMeConfigurer<H> authenticationSuccessHandler(
			AuthenticationSuccessHandler authenticationSuccessHandler) {
		this.authenticationSuccessHandler = authenticationSuccessHandler;
		return this;
	}

	/**
	 * Specify the {@link RememberMeServices} to use.
	 * @param rememberMeServices the {@link RememberMeServices} to use
	 * @return the {@link RememberMeConfigurer} for further customizations
	 * @see RememberMeServices
	 */
	public RememberMeConfigurer<H> rememberMeServices(RememberMeServices rememberMeServices) {
		this.rememberMeServices = rememberMeServices;
		return this;
	}

	/**
	 * Whether the cookie should always be created even if the remember-me parameter is
	 * not set.
	 * <p>
	 * By default this will be set to {@code false}.
	 * @param alwaysRemember set to {@code true} to always trigger remember me,
	 * {@code false} to use the remember-me parameter.
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices#setAlwaysRemember(boolean)
	 */
	public RememberMeConfigurer<H> alwaysRemember(boolean alwaysRemember) {
		this.alwaysRemember = alwaysRemember;
		return this;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void init(H http) throws Exception {
		validateInput();
		//获取秘钥
		String key = getKey();
		//获得记住我服务
		RememberMeServices rememberMeServices = getRememberMeServices(http, key);
		//将记住我服务放入SharedObject中，这样表单登录时候就能够创建记住我令牌了
		http.setSharedObject(RememberMeServices.class, rememberMeServices);

		//记住我服务，通常都实现了登出处理器，提供登出的时候，删除记住我令牌的功能
		LogoutConfigurer<H> logoutConfigurer = http.getConfigurer(LogoutConfigurer.class);
		if (logoutConfigurer != null && this.logoutHandler != null) {
			logoutConfigurer.addLogoutHandler(this.logoutHandler);
		}

		//创建一个记住我用户的认证提供者
		RememberMeAuthenticationProvider authenticationProvider = new RememberMeAuthenticationProvider(key);
		authenticationProvider = postProcess(authenticationProvider);
		//添加到httpSecurity中
		http.authenticationProvider(authenticationProvider);
		//如果有登录页的话，给他设置开启记住我登录的参数名
		initDefaultLoginFilter(http);
	}

	@Override
	public void configure(H http) {
		//创建对应过滤器
		RememberMeAuthenticationFilter rememberMeFilter = new RememberMeAuthenticationFilter(
				http.getSharedObject(AuthenticationManager.class), this.rememberMeServices);
		//设置认证成功处理器
		if (this.authenticationSuccessHandler != null) {
			rememberMeFilter.setAuthenticationSuccessHandler(this.authenticationSuccessHandler);
		}
		rememberMeFilter = postProcess(rememberMeFilter);
		http.addFilter(rememberMeFilter);
	}

	/**
	 * 验证：记住我服务和参数名称必须都存在，不然记住我功能无法正常开启
	 */
	private void validateInput() {
		if (this.rememberMeServices != null && !DEFAULT_REMEMBER_ME_NAME.equals(this.rememberMeCookieName)) {
			throw new IllegalArgumentException("Can not set rememberMeCookieName and custom rememberMeServices.");
		}
	}

	/**
	 * Returns the HTTP parameter used to indicate to remember the user at time of login.
	 * @return the HTTP parameter used to indicate to remember the user
	 */
	private String getRememberMeParameter() {
		return this.rememberMeParameter;
	}

	/**
	 * 如果有登录页的话，给他设置开启记住我登录的参数名
	 */
	private void initDefaultLoginFilter(H http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null) {
			loginPageGeneratingFilter.setRememberMeParameter(getRememberMeParameter());
		}
	}

	/**
	 * 获得记住我服务
	 * @param http
	 * @param key
	 * @return
	 * @throws Exception
	 */
	private RememberMeServices getRememberMeServices(H http, String key) throws Exception {
		//如果记住我服务也是一个登出处理器
		if (this.rememberMeServices != null) {
			if (this.rememberMeServices instanceof LogoutHandler && this.logoutHandler == null) {
				this.logoutHandler = (LogoutHandler) this.rememberMeServices;
			}
			return this.rememberMeServices;
		}
		//创建记住我服务
		AbstractRememberMeServices tokenRememberMeServices = createRememberMeServices(http, key);
		//设置记住我开启参数名称和记住我参数名称
		tokenRememberMeServices.setParameter(this.rememberMeParameter);
		tokenRememberMeServices.setCookieName(this.rememberMeCookieName);

		//设置一些Cookie规则
		if (this.rememberMeCookieDomain != null) {
			tokenRememberMeServices.setCookieDomain(this.rememberMeCookieDomain);
		}
		if (this.tokenValiditySeconds != null) {
			tokenRememberMeServices.setTokenValiditySeconds(this.tokenValiditySeconds);
		}
		if (this.useSecureCookie != null) {
			tokenRememberMeServices.setUseSecureCookie(this.useSecureCookie);
		}
		if (this.alwaysRemember != null) {
			tokenRememberMeServices.setAlwaysRemember(this.alwaysRemember);
		}

		tokenRememberMeServices.afterPropertiesSet();

		//设置登出处理器和记住我服务
		//记住我服务也实现了登出处理器
		this.logoutHandler = tokenRememberMeServices;
		this.rememberMeServices = tokenRememberMeServices;
		return tokenRememberMeServices;
	}

	/**
	 * 创建记住我服务
	 * <p>当没有指定持久化策略的时候，就使用TokenBased</p>
	 */
	private AbstractRememberMeServices createRememberMeServices(H http, String key) {
		return (this.tokenRepository != null) ? createPersistentRememberMeServices(http, key)
				: createTokenBasedRememberMeServices(http, key);
	}

	/**
	 * Creates {@link TokenBasedRememberMeServices}
	 * @param http the {@link HttpSecurity} to lookup shared objects
	 * @param key the {@link #key(String)}
	 * @return the {@link TokenBasedRememberMeServices}
	 */
	private AbstractRememberMeServices createTokenBasedRememberMeServices(H http, String key) {
		UserDetailsService userDetailsService = getUserDetailsService(http);
		return new TokenBasedRememberMeServices(key, userDetailsService);
	}

	/**
	 * Creates {@link PersistentTokenBasedRememberMeServices}
	 * @param http the {@link HttpSecurity} to lookup shared objects
	 * @param key the {@link #key(String)}
	 * @return the {@link PersistentTokenBasedRememberMeServices}
	 */
	private AbstractRememberMeServices createPersistentRememberMeServices(H http, String key) {
		UserDetailsService userDetailsService = getUserDetailsService(http);
		return new PersistentTokenBasedRememberMeServices(key, userDetailsService, this.tokenRepository);
	}

	/**
	 * 获得用户详情服务
	 */
	private UserDetailsService getUserDetailsService(H http) {
		if (this.userDetailsService == null) {
			this.userDetailsService = http.getSharedObject(UserDetailsService.class);
		}
		Assert.state(this.userDetailsService != null,
				() -> "userDetailsService cannot be null. Invoke " + RememberMeConfigurer.class.getSimpleName()
						+ "#userDetailsService(UserDetailsService) or see its javadoc for alternative approaches.");
		return this.userDetailsService;
	}

	/**
	 * 获取key
	 */
	private String getKey() {
		if (this.key == null) {
			if (this.rememberMeServices instanceof AbstractRememberMeServices) {
				this.key = ((AbstractRememberMeServices) this.rememberMeServices).getKey();
			}
			else {
				this.key = UUID.randomUUID().toString();
			}
		}
		return this.key;
	}

}

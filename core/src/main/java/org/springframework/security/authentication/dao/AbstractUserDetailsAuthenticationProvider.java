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

package org.springframework.security.authentication.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.util.Assert;

/**
 * A base {@link AuthenticationProvider} that allows subclasses to override and work with
 * {@link org.springframework.security.core.userdetails.UserDetails} objects. The class is
 * designed to respond to {@link UsernamePasswordAuthenticationToken} authentication
 * requests.
 *
 * <p>
 * Upon successful validation, a <code>UsernamePasswordAuthenticationToken</code> will be
 * created and returned to the caller. The token will include as its principal either a
 * <code>String</code> representation of the username, or the {@link UserDetails} that was
 * returned from the authentication repository. Using <code>String</code> is appropriate
 * if a container adapter is being used, as it expects <code>String</code> representations
 * of the username. Using <code>UserDetails</code> is appropriate if you require access to
 * additional properties of the authenticated user, such as email addresses,
 * human-friendly names etc. As container adapters are not recommended to be used, and
 * <code>UserDetails</code> implementations provide additional flexibility, by default a
 * <code>UserDetails</code> is returned. To override this default, set the
 * {@link #setForcePrincipalAsString} to <code>true</code>.
 * <p>
 * Caching is handled by storing the <code>UserDetails</code> object being placed in the
 * {@link UserCache}. This ensures that subsequent requests with the same username can be
 * validated without needing to query the {@link UserDetailsService}. It should be noted
 * that if a user appears to present an incorrect password, the {@link UserDetailsService}
 * will be queried to confirm the most up-to-date password was used for comparison.
 * Caching is only likely to be required for stateless applications. In a normal web
 * application, for example, the <tt>SecurityContext</tt> is stored in the user's session
 * and the user isn't reauthenticated on each request. The default cache implementation is
 * therefore {@link NullUserCache}.
 *
 * @author Ben Alex
 */
public abstract class AbstractUserDetailsAuthenticationProvider
		implements AuthenticationProvider, InitializingBean, MessageSourceAware {

	protected final Log logger = LogFactory.getLog(getClass());

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	/**
	 * 用户缓存
	 */
	private UserCache userCache = new NullUserCache();

	/**
	 * 认证成功后是否将Principal由原来的UserDetails对象转为用户名
	 */
	private boolean forcePrincipalAsString = false;

	/**
	 * 通过用户名查询UserDetails失败后，是否将异常隐藏，然后抛出统一的异常{@link BadCredentialsException}
	 */
	protected boolean hideUserNotFoundExceptions = true;

	/**
	 * 认证前检查器
	 */
	private UserDetailsChecker preAuthenticationChecks = new DefaultPreAuthenticationChecks();

	/**
	 * 认证后检查器
	 */
	private UserDetailsChecker postAuthenticationChecks = new DefaultPostAuthenticationChecks();

	/**
	 * 认证成功后，进行权限映射
	 */
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	/**
	 * Allows subclasses to perform any additional checks of a returned (or cached)
	 * <code>UserDetails</code> for a given authentication request. Generally a subclass
	 * will at least compare the {@link Authentication#getCredentials()} with a
	 * {@link UserDetails#getPassword()}. If custom logic is needed to compare additional
	 * properties of <code>UserDetails</code> and/or
	 * <code>UsernamePasswordAuthenticationToken</code>, these should also appear in this
	 * method.
	 * @param userDetails as retrieved from the
	 * {@link #retrieveUser(String, UsernamePasswordAuthenticationToken)} or
	 * <code>UserCache</code>
	 * @param authentication the current request that needs to be authenticated
	 * @throws AuthenticationException AuthenticationException if the credentials could
	 * not be validated (generally a <code>BadCredentialsException</code>, an
	 * <code>AuthenticationServiceException</code>)
	 */
	protected abstract void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication) throws AuthenticationException;

	@Override
	public final void afterPropertiesSet() throws Exception {
		Assert.notNull(this.userCache, "A user cache must be set");
		Assert.notNull(this.messages, "A message source must be set");
		doAfterPropertiesSet();
	}

	/**
	 * 进行认证
	 * @param authentication 是由传入的用户名和密码创建的认证对象
	 * @return
	 * @throws AuthenticationException
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
				() -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
						"Only UsernamePasswordAuthenticationToken is supported"));
		String username = determineUsername(authentication);
		//标准是否在缓存中，默认是
		boolean cacheWasUsed = true;
		//尝试从缓存中获取
		UserDetails user = this.userCache.getUserFromCache(username);
		if (user == null) {
			//标记为缓存中没有此用户
			cacheWasUsed = false;
			try {
				//调用UserDetailsService拿到UserDetails
				user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
			}
			catch (UsernameNotFoundException ex) {
				this.logger.debug("Failed to find user '" + username + "'");
				//是否隐藏异常类型
				if (!this.hideUserNotFoundExceptions) {
					throw ex;
				}
				throw new BadCredentialsException(this.messages
						.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
			}
			Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");
		}
		try {
			//认证前检查
			this.preAuthenticationChecks.check(user);
			//进行密码匹配
			additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
		}
		catch (AuthenticationException ex) {
			if (!cacheWasUsed) {
				throw ex;
			}
			//到这就说明，进行比较的用户是在缓存中的，那么就从持久化(比如数据库)的地方中读取最新的UserDetails
			//然后再进行密码匹配
			cacheWasUsed = false;
			user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
			this.preAuthenticationChecks.check(user);
			additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
		}
		//认证后检查器
		this.postAuthenticationChecks.check(user);
		//放入缓存中
		if (!cacheWasUsed) {
			this.userCache.putUserInCache(user);
		}
		Object principalToReturn = user;
		//认证成功后是否将Principal由原来的UserDetails对象转为用户名
		if (this.forcePrincipalAsString) {
			principalToReturn = user.getUsername();
		}
		//创建一个认证成功的认证对象
		return createSuccessAuthentication(principalToReturn, authentication, user);
	}

	/**
	 * 返回Principal，执行此方法时候的Principal是用户名
	 * @param authentication
	 * @return
	 */
	private String determineUsername(Authentication authentication) {
		return (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
	}

	/**
	 * 创建一个认证成功的认证对象
	 * @param principal 主要内容，通常是UserDetails，而不是用户名
	 * @param authentication 由传入的用户名和密码创建的认证对象
	 * @param user 确定并且正确的UserDetails
	 * @return the successful authentication token
	 */
	protected Authentication createSuccessAuthentication(Object principal, Authentication authentication,
			UserDetails user) {
		//创建认证对象

		UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(principal,
				authentication.getCredentials(),
				//这里还会进行权限的映射
				this.authoritiesMapper.mapAuthorities(user.getAuthorities()));
		//更新认证对象的详细信息,通常是一个WebAuthenticationDetails对象
		result.setDetails(authentication.getDetails());
		this.logger.debug("Authenticated user");
		return result;
	}

	/**
	 * 对认证提供者的属性进行操作
	 * @throws Exception
	 */
	protected void doAfterPropertiesSet() throws Exception {
	}

	public UserCache getUserCache() {
		return this.userCache;
	}

	public boolean isForcePrincipalAsString() {
		return this.forcePrincipalAsString;
	}

	public boolean isHideUserNotFoundExceptions() {
		return this.hideUserNotFoundExceptions;
	}

	/**
	 * 允许子类从特定的地方拿到UserDetails(比如说数据库)
	 * 如果提供的凭据不正确，可以立即抛出AuthenticationException
	 * <p>
	 * Subclasses are not required to perform any caching, as the
	 * <code>AbstractUserDetailsAuthenticationProvider</code> will by default cache the
	 * <code>UserDetails</code>. The caching of <code>UserDetails</code> does present
	 * additional complexity as this means subsequent requests that rely on the cache will
	 * need to still have their credentials validated, even if the correctness of
	 * credentials was assured by subclasses adopting a binding-based strategy in this
	 * method. Accordingly it is important that subclasses either disable caching (if they
	 * want to ensure that this method is the only method that is capable of
	 * authenticating a request, as no <code>UserDetails</code> will ever be cached) or
	 * ensure subclasses implement
	 * {@link #additionalAuthenticationChecks(UserDetails, UsernamePasswordAuthenticationToken)}
	 * to compare the credentials of a cached <code>UserDetails</code> with subsequent
	 * authentication requests.
	 * </p>
	 * <p>
	 * Most of the time subclasses will not perform credentials inspection in this method,
	 * instead performing it in
	 * {@link #additionalAuthenticationChecks(UserDetails, UsernamePasswordAuthenticationToken)}
	 * so that code related to credentials validation need not be duplicated across two
	 * methods.
	 * </p>
	 * @param username The username to retrieve
	 * @param authentication The authentication request, which subclasses <em>may</em>
	 * need to perform a binding-based retrieval of the <code>UserDetails</code>
	 * @return the user information (never <code>null</code> - instead an exception should
	 * the thrown)
	 * @throws AuthenticationException if the credentials could not be validated
	 * (generally a <code>BadCredentialsException</code>, an
	 * <code>AuthenticationServiceException</code> or
	 * <code>UsernameNotFoundException</code>)
	 */
	protected abstract UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException;

	public void setForcePrincipalAsString(boolean forcePrincipalAsString) {
		this.forcePrincipalAsString = forcePrincipalAsString;
	}

	/**
	 * By default the <code>AbstractUserDetailsAuthenticationProvider</code> throws a
	 * <code>BadCredentialsException</code> if a username is not found or the password is
	 * incorrect. Setting this property to <code>false</code> will cause
	 * <code>UsernameNotFoundException</code>s to be thrown instead for the former. Note
	 * this is considered less secure than throwing <code>BadCredentialsException</code>
	 * for both exceptions.
	 * @param hideUserNotFoundExceptions set to <code>false</code> if you wish
	 * <code>UsernameNotFoundException</code>s to be thrown instead of the non-specific
	 * <code>BadCredentialsException</code> (defaults to <code>true</code>)
	 */
	public void setHideUserNotFoundExceptions(boolean hideUserNotFoundExceptions) {
		this.hideUserNotFoundExceptions = hideUserNotFoundExceptions;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	public void setUserCache(UserCache userCache) {
		this.userCache = userCache;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
	}

	protected UserDetailsChecker getPreAuthenticationChecks() {
		return this.preAuthenticationChecks;
	}

	/**
	 * Sets the policy will be used to verify the status of the loaded
	 * <tt>UserDetails</tt> <em>before</em> validation of the credentials takes place.
	 * @param preAuthenticationChecks strategy to be invoked prior to authentication.
	 */
	public void setPreAuthenticationChecks(UserDetailsChecker preAuthenticationChecks) {
		this.preAuthenticationChecks = preAuthenticationChecks;
	}

	protected UserDetailsChecker getPostAuthenticationChecks() {
		return this.postAuthenticationChecks;
	}

	public void setPostAuthenticationChecks(UserDetailsChecker postAuthenticationChecks) {
		this.postAuthenticationChecks = postAuthenticationChecks;
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	/**
	 * 在进行密码匹配的之前进行检查
	 */
	private class DefaultPreAuthenticationChecks implements UserDetailsChecker {


		@Override
		public void check(UserDetails user) {
			//账户不能是被锁定的
			if (!user.isAccountNonLocked()) {
				AbstractUserDetailsAuthenticationProvider.this.logger
						.debug("Failed to authenticate since user account is locked");
				throw new LockedException(AbstractUserDetailsAuthenticationProvider.this.messages
						.getMessage("AbstractUserDetailsAuthenticationProvider.locked", "User account is locked"));
			}
			//账户不能是不可用的
			if (!user.isEnabled()) {
				AbstractUserDetailsAuthenticationProvider.this.logger
						.debug("Failed to authenticate since user account is disabled");
				throw new DisabledException(AbstractUserDetailsAuthenticationProvider.this.messages
						.getMessage("AbstractUserDetailsAuthenticationProvider.disabled", "User is disabled"));
			}
			//账户不能是已经过期的
			if (!user.isAccountNonExpired()) {
				AbstractUserDetailsAuthenticationProvider.this.logger
						.debug("Failed to authenticate since user account has expired");
				throw new AccountExpiredException(AbstractUserDetailsAuthenticationProvider.this.messages
						.getMessage("AbstractUserDetailsAuthenticationProvider.expired", "User account has expired"));
			}
		}

	}

	private class DefaultPostAuthenticationChecks implements UserDetailsChecker {

		@Override
		public void check(UserDetails user) {
			//确定密码是否过期
			if (!user.isCredentialsNonExpired()) {
				AbstractUserDetailsAuthenticationProvider.this.logger
						.debug("Failed to authenticate since user account credentials have expired");
				throw new CredentialsExpiredException(AbstractUserDetailsAuthenticationProvider.this.messages
						.getMessage("AbstractUserDetailsAuthenticationProvider.credentialsExpired",
								"User credentials have expired"));
			}
		}

	}

}

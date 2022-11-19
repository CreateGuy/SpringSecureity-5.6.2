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

package org.springframework.security.authentication;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * 认证管理器，通过认证提供者进行认证
 *
 * <p>
 * <tt>AuthenticationProvider</tt>s are usually tried in order until one provides a
 * non-null response. A non-null response indicates the provider had authority to decide
 * on the authentication request and no further providers are tried. If a subsequent
 * provider successfully authenticates the request, the earlier authentication exception
 * is disregarded and the successful authentication will be used. If no subsequent
 * provider provides a non-null response, or a new <code>AuthenticationException</code>,
 * the last <code>AuthenticationException</code> received will be used. If no provider
 * returns a non-null response, or indicates it can even process an
 * <code>Authentication</code>, the <code>ProviderManager</code> will throw a
 * <code>ProviderNotFoundException</code>. A parent {@code AuthenticationManager} can also
 * be set, and this will also be tried if none of the configured providers can perform the
 * authentication. This is intended to support namespace configuration options though and
 * is not a feature that should normally be required.
 * <p>
 * The exception to this process is when a provider throws an
 * {@link AccountStatusException}, in which case no further providers in the list will be
 * queried.
 *
 * Post-authentication, the credentials will be cleared from the returned
 * {@code Authentication} object, if it implements the {@link CredentialsContainer}
 * interface. This behaviour can be controlled by modifying the
 * {@link #setEraseCredentialsAfterAuthentication(boolean)
 * eraseCredentialsAfterAuthentication} property.
 *
 * <h2>Event Publishing</h2>
 * <p>
 * Authentication event publishing is delegated to the configured
 * {@link AuthenticationEventPublisher} which defaults to a null implementation which
 * doesn't publish events, so if you are configuring the bean yourself you must inject a
 * publisher bean if you want to receive events. The standard implementation is
 * {@link DefaultAuthenticationEventPublisher} which maps common exceptions to events (in
 * the case of authentication failure) and publishes an
 * {@link org.springframework.security.authentication.event.AuthenticationSuccessEvent
 * AuthenticationSuccessEvent} if authentication succeeds. If you are using the namespace
 * then an instance of this bean will be used automatically by the <tt>&lt;http&gt;</tt>
 * configuration, so you will receive events from the web part of your application
 * automatically.
 * <p>
 * Note that the implementation also publishes authentication failure events when it
 * obtains an authentication result (or an exception) from the "parent"
 * {@code AuthenticationManager} if one has been set. So in this situation, the parent
 * should not generally be configured to publish events or there will be duplicates.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @see DefaultAuthenticationEventPublisher
 */
public class ProviderManager implements AuthenticationManager, MessageSourceAware, InitializingBean {

	private static final Log logger = LogFactory.getLog(ProviderManager.class);

	/**
	 * 认证事件推送器，内部也是借助了事件推送器({@link org.springframework.context.ApplicationEventPublisher})
	 */
	private AuthenticationEventPublisher eventPublisher = new NullEventPublisher();

	/**
	 * 当前认证管理器的认证提供者
	 */
	private List<AuthenticationProvider> providers = Collections.emptyList();

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	/**
	 * 全局认证管理器
	 */
	private AuthenticationManager parent;

	/**
	 * 是否在认证成功后清除密码
	 */
	private boolean eraseCredentialsAfterAuthentication = true;

	/**
	 * Construct a {@link ProviderManager} using the given {@link AuthenticationProvider}s
	 * @param providers the {@link AuthenticationProvider}s to use
	 */
	public ProviderManager(AuthenticationProvider... providers) {
		this(Arrays.asList(providers), null);
	}

	/**
	 * Construct a {@link ProviderManager} using the given {@link AuthenticationProvider}s
	 * @param providers the {@link AuthenticationProvider}s to use
	 */
	public ProviderManager(List<AuthenticationProvider> providers) {
		this(providers, null);
	}

	/**
	 * Construct a {@link ProviderManager} using the provided parameters
	 * @param providers the {@link AuthenticationProvider}s to use
	 * @param parent a parent {@link AuthenticationManager} to fall back to
	 */
	public ProviderManager(List<AuthenticationProvider> providers, AuthenticationManager parent) {
		Assert.notNull(providers, "providers list cannot be null");
		this.providers = providers;
		this.parent = parent;
		checkState();
	}

	@Override
	public void afterPropertiesSet() {
		checkState();
	}

	private void checkState() {
		Assert.isTrue(this.parent != null || !this.providers.isEmpty(),
				"A parent AuthenticationManager or a list of AuthenticationProviders is required");
		Assert.isTrue(!CollectionUtils.contains(this.providers.iterator(), null),
				"providers list cannot contain null values");
	}

	/**
	 * 对传入的认证对象进行认证
	 * @param authentication 通常是由系统通过某些参数构建的，比如说前端传入的用户名和密码
	 * @return
	 * @throws AuthenticationException
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		//获得认证对象的类型
		Class<? extends Authentication> toTest = authentication.getClass();
		//通过局部和全局认证管理器认证出现的异常
		AuthenticationException lastException = null;
		AuthenticationException parentException = null;

		//通过局部和全局认证管理器认证，最终保存到安全上下文的认证对象
		Authentication result = null;
		Authentication parentResult = null;

		int currentPosition = 0;
		int size = this.providers.size();
		for (AuthenticationProvider provider : getProviders()) {
			//判断当前认证提供者是否支持这个认证对象
			if (!provider.supports(toTest)) {
				continue;
			}
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Authenticating request with %s (%d/%d)",
						provider.getClass().getSimpleName(), ++currentPosition, size));
			}
			try {
				//进行认证
				result = provider.authenticate(authentication);
				if (result != null) {
					//复制详细信息到新的认证对象中
					copyDetails(authentication, result);
					break;
				}
			}
			catch (AccountStatusException | InternalAuthenticationServiceException ex) {
				prepareException(ex, authentication);
				//如果认证失败是由于无效的帐户状态导致的，则抛出异常，避免轮询执行其他认证提供者
				throw ex;
			}
			catch (AuthenticationException ex) {
				lastException = ex;
			}
		}
		//到这就说明局部管理器无法认证，尝试调用父类(全局认证管理器)
		if (result == null && this.parent != null) {
			try {
				//进行认证
				parentResult = this.parent.authenticate(authentication);
				//两个都有了
				result = parentResult;
			}
			catch (ProviderNotFoundException ex) {
				// ignore as we will throw below if no other exception occurred prior to
				// calling parent and the parent
				// may throw ProviderNotFound even though a provider in the child already
				// handled the request
			}
			catch (AuthenticationException ex) {
				parentException = ex;
				lastException = ex;
			}
		}
		//如果认证成功
		if (result != null) {
			//是否在认证成功后清除敏感数据
			if (this.eraseCredentialsAfterAuthentication && (result instanceof CredentialsContainer)) {
				//比如说清除密码
				((CredentialsContainer) result).eraseCredentials();
			}

			//如果是局部自己就认证成功的，发布一个认证成功事件
			if (parentResult == null) {
				this.eventPublisher.publishAuthenticationSuccess(result);
			}

			return result;
		}

		//如果中途抛出了异常
		if (lastException == null) {
			//统一包装成一个异常
			lastException = new ProviderNotFoundException(this.messages.getMessage("ProviderManager.providerNotFound",
					new Object[] { toTest.getName() }, "No AuthenticationProvider found for {0}"));
		}
		//如果只是局部抛出了，就发布一个认证失败异常
		if (parentException == null) {
			prepareException(lastException, authentication);
		}
		throw lastException;
	}

	/**
	 * 推送一个认证失败的事件
	 * @param ex
	 * @param auth
	 */
	@SuppressWarnings("deprecation")
	private void prepareException(AuthenticationException ex, Authentication auth) {
		this.eventPublisher.publishAuthenticationFailure(ex, auth);
	}

	/**
	 * 将身份验证详细信息从旧的认证对象复制到新认证对象中，前提是后者还没有一个集合。
	 * @param source
	 * @param dest
	 */
	private void copyDetails(Authentication source, Authentication dest) {
		if ((dest instanceof AbstractAuthenticationToken) && (dest.getDetails() == null)) {
			AbstractAuthenticationToken token = (AbstractAuthenticationToken) dest;
			token.setDetails(source.getDetails());
		}
	}

	public List<AuthenticationProvider> getProviders() {
		return this.providers;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	public void setAuthenticationEventPublisher(AuthenticationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "AuthenticationEventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
	}

	/**
	 * If set to, a resulting {@code Authentication} which implements the
	 * {@code CredentialsContainer} interface will have its
	 * {@link CredentialsContainer#eraseCredentials() eraseCredentials} method called
	 * before it is returned from the {@code authenticate()} method.
	 * @param eraseSecretData set to {@literal false} to retain the credentials data in
	 * memory. Defaults to {@literal true}.
	 */
	public void setEraseCredentialsAfterAuthentication(boolean eraseSecretData) {
		this.eraseCredentialsAfterAuthentication = eraseSecretData;
	}

	public boolean isEraseCredentialsAfterAuthentication() {
		return this.eraseCredentialsAfterAuthentication;
	}

	private static final class NullEventPublisher implements AuthenticationEventPublisher {

		@Override
		public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		}

		@Override
		public void publishAuthenticationSuccess(Authentication authentication) {
		}

	}

}

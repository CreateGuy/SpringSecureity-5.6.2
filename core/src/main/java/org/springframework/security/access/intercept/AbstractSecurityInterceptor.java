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

package org.springframework.security.access.intercept;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.event.AuthenticationCredentialsNotFoundEvent;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.access.event.AuthorizedEvent;
import org.springframework.security.access.event.PublicInvocationEvent;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * Abstract class that implements security interception for secure objects.
 * <p>
 * The <code>AbstractSecurityInterceptor</code> will ensure the proper startup
 * configuration of the security interceptor. It will also implement the proper handling
 * of secure object invocations, namely:
 * <ol>
 * <li>Obtain the {@link Authentication} object from the
 * {@link SecurityContextHolder}.</li>
 * <li>Determine if the request relates to a secured or public invocation by looking up
 * the secure object request against the {@link SecurityMetadataSource}.</li>
 * <li>For an invocation that is secured (there is a list of <code>ConfigAttribute</code>s
 * for the secure object invocation):
 * <ol type="a">
 * <li>If either the
 * {@link org.springframework.security.core.Authentication#isAuthenticated()} returns
 * <code>false</code>, or the {@link #alwaysReauthenticate} is <code>true</code>,
 * authenticate the request against the configured {@link AuthenticationManager}. When
 * authenticated, replace the <code>Authentication</code> object on the
 * <code>SecurityContextHolder</code> with the returned value.</li>
 * <li>Authorize the request against the configured {@link AccessDecisionManager}.</li>
 * <li>Perform any run-as replacement via the configured {@link RunAsManager}.</li>
 * <li>Pass control back to the concrete subclass, which will actually proceed with
 * executing the object. A {@link InterceptorStatusToken} is returned so that after the
 * subclass has finished proceeding with execution of the object, its finally clause can
 * ensure the <code>AbstractSecurityInterceptor</code> is re-called and tidies up
 * correctly using {@link #finallyInvocation(InterceptorStatusToken)}.</li>
 * <li>The concrete subclass will re-call the <code>AbstractSecurityInterceptor</code> via
 * the {@link #afterInvocation(InterceptorStatusToken, Object)} method.</li>
 * <li>If the <code>RunAsManager</code> replaced the <code>Authentication</code> object,
 * return the <code>SecurityContextHolder</code> to the object that existed after the call
 * to <code>AuthenticationManager</code>.</li>
 * <li>If an <code>AfterInvocationManager</code> is defined, invoke the invocation manager
 * and allow it to replace the object due to be returned to the caller.</li>
 * </ol>
 * </li>
 * <li>For an invocation that is public (there are no <code>ConfigAttribute</code>s for
 * the secure object invocation):
 * <ol type="a">
 * <li>As described above, the concrete subclass will be returned an
 * <code>InterceptorStatusToken</code> which is subsequently re-presented to the
 * <code>AbstractSecurityInterceptor</code> after the secure object has been executed. The
 * <code>AbstractSecurityInterceptor</code> will take no further action when its
 * {@link #afterInvocation(InterceptorStatusToken, Object)} is called.</li>
 * </ol>
 * </li>
 * <li>Control again returns to the concrete subclass, along with the <code>Object</code>
 * that should be returned to the caller. The subclass will then return that result or
 * exception to the original caller.</li>
 * </ol>
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public abstract class AbstractSecurityInterceptor
		implements InitializingBean, ApplicationEventPublisherAware, MessageSourceAware {

	protected final Log logger = LogFactory.getLog(getClass());

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	/**
	 * 事件推送器
	 */
	private ApplicationEventPublisher eventPublisher;

	/**
	 * 访问决策管理器
	 */
	private AccessDecisionManager accessDecisionManager;

	/**
	 * 执行后管理器
	 */
	private AfterInvocationManager afterInvocationManager;

	/**
	 * 局部认证管理器
	 */
	private AuthenticationManager authenticationManager = new NoOpAuthenticationManager();

	private RunAsManager runAsManager = new NullRunAsManager();

	/**
	 * 是否一直 通过局部认证管理器获得认证对象
	 */
	private boolean alwaysReauthenticate = false;

	/**
	 * 接口没有要求权限的时候，视为公共接口，猜测是否拒绝访问公共接口
	 */
	private boolean rejectPublicInvocations = false;

	/**
	 * 是否开启验证权限表达式(ConfigAttribute)
	 */
	private boolean validateConfigAttributes = true;

	/**
	 * 是否在权限判断成功后发布特定的事件
	 */
	private boolean publishAuthorizationSuccess = false;

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(getSecureObjectClass(), "Subclass must provide a non-null response to getSecureObjectClass()");
		Assert.notNull(this.messages, "A message source must be set");
		Assert.notNull(this.authenticationManager, "An AuthenticationManager is required");
		Assert.notNull(this.accessDecisionManager, "An AccessDecisionManager is required");
		Assert.notNull(this.runAsManager, "A RunAsManager is required");
		Assert.notNull(this.obtainSecurityMetadataSource(), "An SecurityMetadataSource is required");
		Assert.isTrue(this.obtainSecurityMetadataSource().supports(getSecureObjectClass()),
				() -> "SecurityMetadataSource does not support secure object class: " + getSecureObjectClass());
		Assert.isTrue(this.runAsManager.supports(getSecureObjectClass()),
				() -> "RunAsManager does not support secure object class: " + getSecureObjectClass());
		Assert.isTrue(this.accessDecisionManager.supports(getSecureObjectClass()),
				() -> "AccessDecisionManager does not support secure object class: " + getSecureObjectClass());
		if (this.afterInvocationManager != null) {
			Assert.isTrue(this.afterInvocationManager.supports(getSecureObjectClass()),
					() -> "AfterInvocationManager does not support secure object class: " + getSecureObjectClass());
		}

		//是否开启验证权限表达式
		if (this.validateConfigAttributes) {
			//通过安全元数据获得保存的所有权限表达式
			Collection<ConfigAttribute> attributeDefs = this.obtainSecurityMetadataSource().getAllConfigAttributes();
			if (attributeDefs == null) {
				this.logger.warn("Could not validate configuration attributes as the "
						+ "SecurityMetadataSource did not return any attributes from getAllConfigAttributes()");
				return;
			}
			//验证权限表达式(ConfigAttribute)
			validateAttributeDefs(attributeDefs);
		}
	}

	/**
	 * 验证权限表达式(ConfigAttribute)
	 * @param attributeDefs
	 */
	private void validateAttributeDefs(Collection<ConfigAttribute> attributeDefs) {
		Set<ConfigAttribute> unsupportedAttrs = new HashSet<>();
		for (ConfigAttribute attr : attributeDefs) {
			if (!this.runAsManager.supports(attr) && !this.accessDecisionManager.supports(attr)
					&& ((this.afterInvocationManager == null) || !this.afterInvocationManager.supports(attr))) {
				unsupportedAttrs.add(attr);
			}
		}

		//有任何一个不支持就抛出异常
		if (unsupportedAttrs.size() != 0) {
			this.logger
					.trace("Did not validate configuration attributes since validateConfigurationAttributes is false");
			throw new IllegalArgumentException("Unsupported configuration attributes: " + unsupportedAttrs);
		}
		else {
			this.logger.trace("Validated configuration attributes");
		}
	}

	/**
	 * 执行调用前的权限判断
	 * @param object
	 * @return
	 */
	protected InterceptorStatusToken beforeInvocation(Object object) {
		Assert.notNull(object, "Object was null");
		// 当前类支持的类型
		if (!getSecureObjectClass().isAssignableFrom(object.getClass())) {
			throw new IllegalArgumentException("Security invocation attempted for object " + object.getClass().getName()
					+ " but AbstractSecurityInterceptor only configured to support secure objects of type: "
					+ getSecureObjectClass());
		}
		//通过安全元数据获得接口所需权限
		Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource().getAttributes(object);

		//当不需要任何权限的时候
		if (CollectionUtils.isEmpty(attributes)) {
			Assert.isTrue(!this.rejectPublicInvocations,
					() -> "Secure object invocation " + object
							+ " was denied as public invocations are not allowed via this interceptor. "
							+ "This indicates a configuration error because the "
							+ "rejectPublicInvocations property is set to 'true'");
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Authorized public object %s", object));
			}
			//发布特定事件
			publishEvent(new PublicInvocationEvent(object));
			return null;
		}

		//确定有认证对象
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			//发布认证对象未找到事件
			credentialsNotFound(this.messages.getMessage("AbstractSecurityInterceptor.authenticationNotFound",
					"An Authentication object was not found in the SecurityContext"), object, attributes);
		}
		//获得认对象
		Authentication authenticated = authenticateIfRequired();
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Authorizing %s with attributes %s", object, attributes));
		}
		// 调用访问决策管理器进行权限判断
		attemptAuthorization(object, attributes, authenticated);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Authorized %s with attributes %s", object, attributes));
		}

		//发布特定的事件
		if (this.publishAuthorizationSuccess) {
			publishEvent(new AuthorizedEvent(object, attributes, authenticated));
		}

		//尝试以不同的用户执行
		Authentication runAs = this.runAsManager.buildRunAs(authenticated, object, attributes);

		//更新线程级别上下文策略中的认证对象
		if (runAs != null) {
			SecurityContext origCtx = SecurityContextHolder.getContext();
			SecurityContext newCtx = SecurityContextHolder.createEmptyContext();
			newCtx.setAuthentication(runAs);
			SecurityContextHolder.setContext(newCtx);

			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Switched to RunAs authentication %s", runAs));
			}
			//第二个参数表示：需要恢复认证对象
			return new InterceptorStatusToken(origCtx, true, attributes, object);
		}
		this.logger.trace("Did not switch RunAs authentication since RunAsManager returned null");
		//第二个参数表示：需要不需要恢复认证对象
		return new InterceptorStatusToken(SecurityContextHolder.getContext(), false, attributes, object);

	}

	/**
	 * 调用访问决策管理器进行权限判断
	 * @param object
	 * @param attributes 接口所需权限
	 * @param authenticated 认证对象
	 */
	private void attemptAuthorization(Object object, Collection<ConfigAttribute> attributes,
			Authentication authenticated) {
		try {
			//调用访问决策管理器确定是否放行该请求
			this.accessDecisionManager.decide(authenticated, object, attributes);
		}
		catch (AccessDeniedException ex) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Failed to authorize %s with attributes %s using %s", object,
						attributes, this.accessDecisionManager));
			}
			else if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Failed to authorize %s with attributes %s", object, attributes));
			}
			//推送对应的事件
			publishEvent(new AuthorizationFailureEvent(object, attributes, authenticated, ex));
			throw ex;
		}
	}

	/**
	 * 是否需要将认证对象恢复到 判断权限之前
	 * @param token
	 */
	protected void finallyInvocation(InterceptorStatusToken token) {
		/*
			这个if成立的情况一般都是RunAsUserToken的认证对象的情况
			由于RunAsUserToken是新增了一些权限的，所以需要刷新回去
		 */
		if (token != null && token.isContextHolderRefreshRequired()) {
			SecurityContextHolder.setContext(token.getSecurityContext());
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.of(
						() -> "Reverted to original authentication " + token.getSecurityContext().getAuthentication()));
			}
		}
	}

	/**
	 * Completes the work of the <tt>AbstractSecurityInterceptor</tt> after the secure
	 * object invocation has been completed.
	 * @param token as returned by the {@link #beforeInvocation(Object)} method
	 * @param returnedObject any object returned from the secure object invocation (may be
	 * <tt>null</tt>)
	 * @return the object the secure object invocation should ultimately return to its
	 * caller (may be <tt>null</tt>)
	 */
	protected Object afterInvocation(InterceptorStatusToken token, Object returnedObject) {
		//如果token为空，就说接口是一个公共接口，不需要权限，就直接返回
		if (token == null) {
			return returnedObject;
		}
		//是否需要将认证对象恢复到 判断权限之前
		finallyInvocation(token);
		if (this.afterInvocationManager != null) {
			try {
				//处理之后目标方法后的操作
				returnedObject = this.afterInvocationManager.decide(token.getSecurityContext().getAuthentication(),
						token.getSecureObject(), token.getAttributes(), returnedObject);
			}
			catch (AccessDeniedException ex) {
				//发布授权失败异常
				publishEvent(new AuthorizationFailureEvent(token.getSecureObject(), token.getAttributes(),
						token.getSecurityContext().getAuthentication(), ex));
				throw ex;
			}
		}
		return returnedObject;
	}

	/**
	 * 获得认对象
	 * @return
	 */
	private Authentication authenticateIfRequired() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		//是否直接线程级别的安全上下文策略中的 认证对象
		if (authentication.isAuthenticated() && !this.alwaysReauthenticate) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Did not re-authenticate %s before authorizing", authentication));
			}
			return authentication;
		}
		//对传入的认证对象进行认证
		authentication = this.authenticationManager.authenticate(authentication);

		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Re-authenticated %s before authorizing", authentication));
		}

		//重新将安全上下文写入线程级别安全上下文策略中
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		SecurityContextHolder.setContext(context);
		return authentication;
	}

	/**
	 * 发布认证对象未找到事件
	 * @param reason
	 * @param secureObject
	 * @param configAttribs
	 */
	private void credentialsNotFound(String reason, Object secureObject, Collection<ConfigAttribute> configAttribs) {
		AuthenticationCredentialsNotFoundException exception = new AuthenticationCredentialsNotFoundException(reason);
		AuthenticationCredentialsNotFoundEvent event = new AuthenticationCredentialsNotFoundEvent(secureObject,
				configAttribs, exception);
		publishEvent(event);
		throw exception;
	}

	public AccessDecisionManager getAccessDecisionManager() {
		return this.accessDecisionManager;
	}

	public AfterInvocationManager getAfterInvocationManager() {
		return this.afterInvocationManager;
	}

	public AuthenticationManager getAuthenticationManager() {
		return this.authenticationManager;
	}

	public RunAsManager getRunAsManager() {
		return this.runAsManager;
	}

	/**
	 * Indicates the type of secure objects the subclass will be presenting to the
	 * abstract parent for processing. This is used to ensure collaborators wired to the
	 * {@code AbstractSecurityInterceptor} all support the indicated secure object class.
	 * @return the type of secure object the subclass provides services for
	 */
	public abstract Class<?> getSecureObjectClass();

	public boolean isAlwaysReauthenticate() {
		return this.alwaysReauthenticate;
	}

	public boolean isRejectPublicInvocations() {
		return this.rejectPublicInvocations;
	}

	public boolean isValidateConfigAttributes() {
		return this.validateConfigAttributes;
	}

	public abstract SecurityMetadataSource obtainSecurityMetadataSource();

	public void setAccessDecisionManager(AccessDecisionManager accessDecisionManager) {
		this.accessDecisionManager = accessDecisionManager;
	}

	public void setAfterInvocationManager(AfterInvocationManager afterInvocationManager) {
		this.afterInvocationManager = afterInvocationManager;
	}

	/**
	 * Indicates whether the <code>AbstractSecurityInterceptor</code> should ignore the
	 * {@link Authentication#isAuthenticated()} property. Defaults to <code>false</code>,
	 * meaning by default the <code>Authentication.isAuthenticated()</code> property is
	 * trusted and re-authentication will not occur if the principal has already been
	 * authenticated.
	 * @param alwaysReauthenticate <code>true</code> to force
	 * <code>AbstractSecurityInterceptor</code> to disregard the value of
	 * <code>Authentication.isAuthenticated()</code> and always re-authenticate the
	 * request (defaults to <code>false</code>).
	 */
	public void setAlwaysReauthenticate(boolean alwaysReauthenticate) {
		this.alwaysReauthenticate = alwaysReauthenticate;
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

	public void setAuthenticationManager(AuthenticationManager newManager) {
		this.authenticationManager = newManager;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	/**
	 * Only {@code AuthorizationFailureEvent} will be published. If you set this property
	 * to {@code true}, {@code AuthorizedEvent}s will also be published.
	 * @param publishAuthorizationSuccess default value is {@code false}
	 */
	public void setPublishAuthorizationSuccess(boolean publishAuthorizationSuccess) {
		this.publishAuthorizationSuccess = publishAuthorizationSuccess;
	}

	/**
	 * By rejecting public invocations (and setting this property to <tt>true</tt>),
	 * essentially you are ensuring that every secure object invocation advised by
	 * <code>AbstractSecurityInterceptor</code> has a configuration attribute defined.
	 * This is useful to ensure a "fail safe" mode where undeclared secure objects will be
	 * rejected and configuration omissions detected early. An
	 * <tt>IllegalArgumentException</tt> will be thrown by the
	 * <tt>AbstractSecurityInterceptor</tt> if you set this property to <tt>true</tt> and
	 * an attempt is made to invoke a secure object that has no configuration attributes.
	 * @param rejectPublicInvocations set to <code>true</code> to reject invocations of
	 * secure objects that have no configuration attributes (by default it is
	 * <code>false</code> which treats undeclared secure objects as "public" or
	 * unauthorized).
	 */
	public void setRejectPublicInvocations(boolean rejectPublicInvocations) {
		this.rejectPublicInvocations = rejectPublicInvocations;
	}

	public void setRunAsManager(RunAsManager runAsManager) {
		this.runAsManager = runAsManager;
	}

	public void setValidateConfigAttributes(boolean validateConfigAttributes) {
		this.validateConfigAttributes = validateConfigAttributes;
	}

	private void publishEvent(ApplicationEvent event) {
		if (this.eventPublisher != null) {
			this.eventPublisher.publishEvent(event);
		}
	}

	private static class NoOpAuthenticationManager implements AuthenticationManager {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			throw new AuthenticationServiceException("Cannot authenticate " + authentication);
		}

	}

}

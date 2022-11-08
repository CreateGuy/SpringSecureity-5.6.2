/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.web.context;

import javax.servlet.AsyncContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.Transient;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.util.WebUtils;

/**
 * 安全上下文放在{@link HttpSession}中的策略
 * <p>
 * The {@code HttpSession} will be queried to retrieve the {@code SecurityContext} in the
 * <tt>loadContext</tt> method (using the key {@link #SPRING_SECURITY_CONTEXT_KEY} by
 * default). If a valid {@code SecurityContext} cannot be obtained from the
 * {@code HttpSession} for whatever reason, a fresh {@code SecurityContext} will be
 * created by calling by {@link SecurityContextHolder#createEmptyContext()} and this
 * instance will be returned instead.
 * <p>
 * When <tt>saveContext</tt> is called, the context will be stored under the same key,
 * provided
 * <ol>
 * <li>The value has changed</li>
 * <li>The configured <tt>AuthenticationTrustResolver</tt> does not report that the
 * contents represent an anonymous user</li>
 * </ol>
 * <p>
 * With the standard configuration, no {@code HttpSession} will be created during
 * <tt>loadContext</tt> if one does not already exist. When <tt>saveContext</tt> is called
 * at the end of the web request, and no session exists, a new {@code HttpSession} will
 * <b>only</b> be created if the supplied {@code SecurityContext} is not equal to an empty
 * {@code SecurityContext} instance. This avoids needless <code>HttpSession</code>
 * creation, but automates the storage of changes made to the context during the request.
 * Note that if {@link SecurityContextPersistenceFilter} is configured to eagerly create
 * sessions, then the session-minimisation logic applied here will not make any
 * difference. If you are using eager session creation, then you should ensure that the
 * <tt>allowSessionCreation</tt> property of this class is set to <tt>true</tt> (the
 * default).
 * <p>
 * If for whatever reason no {@code HttpSession} should <b>ever</b> be created (for
 * example, if Basic authentication is being used or similar clients that will never
 * present the same {@code jsessionid}), then {@link #setAllowSessionCreation(boolean)
 * allowSessionCreation} should be set to <code>false</code>. Only do this if you really
 * need to conserve server memory and ensure all classes using the
 * {@code SecurityContextHolder} are designed to have no persistence of the
 * {@code SecurityContext} between web requests.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class HttpSessionSecurityContextRepository implements SecurityContextRepository {

	/**
	 * 安全上下文放在HttpSession中的默认key
	 */
	public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

	protected final Log logger = LogFactory.getLog(this.getClass());

	/**
	 * 用于比较是否是空安全上下文的
	 */
	private final Object contextObject = SecurityContextHolder.createEmptyContext();

	/**
	 * 是否允许创建HttpSession
	 */
	private boolean allowSessionCreation = true;

	/**
	 * 不懂
	 */
	private boolean disableUrlRewriting = false;

	/**
	 * 安全上下文放在HttpSession中的key
	 */
	private String springSecurityContextKey = SPRING_SECURITY_CONTEXT_KEY;

	/**
	 * 认证对象解析器
	 */
	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	/**
	 * 从HttpSession加载安全上下文
	 * @param requestResponseHolder
	 * @return
	 */
	@Override
	public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
		HttpServletRequest request = requestResponseHolder.getRequest();
		HttpServletResponse response = requestResponseHolder.getResponse();
		//false表示有就获取，没有就返回空HttpSession
		HttpSession httpSession = request.getSession(false);
		//从HttpSession获取安全存储上下文
		SecurityContext context = readSecurityContextFromSession(httpSession);
		if (context == null) {
			//如果没有找到安全上下文，那就创建一个空安全上下文
			context = generateNewContext();
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Created %s", context));
			}
		}
		//创建response包装类，目的是为了更新安全上下文
		SaveToSessionResponseWrapper wrappedResponse = new SaveToSessionResponseWrapper(response, request,
				httpSession != null, context);
		requestResponseHolder.setResponse(wrappedResponse);
		requestResponseHolder.setRequest(new SaveToSessionRequestWrapper(request, wrappedResponse));
		return context;
	}

	@Override
	public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
		SaveContextOnUpdateOrErrorResponseWrapper responseWrapper = WebUtils.getNativeResponse(response,
				SaveContextOnUpdateOrErrorResponseWrapper.class);
		Assert.state(responseWrapper != null, () -> "Cannot invoke saveContext on response " + response
				+ ". You must use the HttpRequestResponseHolder.response after invoking loadContext");
		responseWrapper.saveContext(context);
	}

	@Override
	public boolean containsContext(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return false;
		}
		return session.getAttribute(this.springSecurityContextKey) != null;
	}

	/**
	 * 从HttpSession获取安全存储上下文
	 */
	private SecurityContext readSecurityContextFromSession(HttpSession httpSession) {
		if (httpSession == null) {
			this.logger.trace("No HttpSession currently exists");
			return null;
		}
		//HttpSession已经存在，因此尝试从中获取安全上下文。
		Object contextFromSession = httpSession.getAttribute(this.springSecurityContextKey);
		if (contextFromSession == null) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Did not find SecurityContext in HttpSession %s "
						+ "using the SPRING_SECURITY_CONTEXT session attribute", httpSession.getId()));
			}
			return null;
		}

		//到这就表示当前会话确实存储了的安全上下文对象
		//要确保保存的安全上下文是正确类型的
		//比如说可能其他地方用了相同的key
		if (!(contextFromSession instanceof SecurityContext)) {
			this.logger.warn(LogMessage.format(
					"%s did not contain a SecurityContext but contained: '%s'; are you improperly "
							+ "modifying the HttpSession directly (you should always use SecurityContextHolder) "
							+ "or using the HttpSession attribute reserved for this class?",
					this.springSecurityContextKey, contextFromSession));
			return null;
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace(
					LogMessage.format("Retrieved %s from %s", contextFromSession, this.springSecurityContextKey));
		}
		else if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Retrieved %s", contextFromSession));
		}
		//准备好了，返回安全上下文
		return (SecurityContext) contextFromSession;
	}

	/**
	 * By default, calls {@link SecurityContextHolder#createEmptyContext()} to obtain a
	 * new context (there should be no context present in the holder when this method is
	 * called). Using this approach the context creation strategy is decided by the
	 * {@link SecurityContextHolderStrategy} in use. The default implementations will
	 * return a new <tt>SecurityContextImpl</tt>.
	 * @return a new SecurityContext instance. Never null.
	 */
	protected SecurityContext generateNewContext() {
		return SecurityContextHolder.createEmptyContext();
	}

	/**
	 * If set to true (the default), a session will be created (if required) to store the
	 * security context if it is determined that its contents are different from the
	 * default empty context value.
	 * <p>
	 * Note that setting this flag to false does not prevent this class from storing the
	 * security context. If your application (or another filter) creates a session, then
	 * the security context will still be stored for an authenticated user.
	 * @param allowSessionCreation
	 */
	public void setAllowSessionCreation(boolean allowSessionCreation) {
		this.allowSessionCreation = allowSessionCreation;
	}

	/**
	 * Allows the use of session identifiers in URLs to be disabled. Off by default.
	 * @param disableUrlRewriting set to <tt>true</tt> to disable URL encoding methods in
	 * the response wrapper and prevent the use of <tt>jsessionid</tt> parameters.
	 */
	public void setDisableUrlRewriting(boolean disableUrlRewriting) {
		this.disableUrlRewriting = disableUrlRewriting;
	}

	/**
	 * Allows the session attribute name to be customized for this repository instance.
	 * @param springSecurityContextKey the key under which the security context will be
	 * stored. Defaults to {@link #SPRING_SECURITY_CONTEXT_KEY}.
	 */
	public void setSpringSecurityContextKey(String springSecurityContextKey) {
		Assert.hasText(springSecurityContextKey, "springSecurityContextKey cannot be empty");
		this.springSecurityContextKey = springSecurityContextKey;
	}

	/**
	 * 如果是即时的认证对象
	 * 我理解是即时的，很快就用完了，那么就没必要去保存了
	 * @param authentication
	 * @return
	 */
	private boolean isTransientAuthentication(Authentication authentication) {
		return AnnotationUtils.getAnnotation(authentication.getClass(), Transient.class) != null;
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. The default is
	 * {@link AuthenticationTrustResolverImpl}.
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
	 * null.
	 */
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		this.trustResolver = trustResolver;
	}

	private static class SaveToSessionRequestWrapper extends HttpServletRequestWrapper {

		private final SaveContextOnUpdateOrErrorResponseWrapper response;

		SaveToSessionRequestWrapper(HttpServletRequest request, SaveContextOnUpdateOrErrorResponseWrapper response) {
			super(request);
			this.response = response;
		}

		@Override
		public AsyncContext startAsync() {
			this.response.disableSaveOnResponseCommitted();
			return super.startAsync();
		}

		@Override
		public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse)
				throws IllegalStateException {
			this.response.disableSaveOnResponseCommitted();
			return super.startAsync(servletRequest, servletResponse);
		}

	}

	/**
	 * 对于Response的包装器：以便在发生sendError()或sendRedirect等等时候之前。如果更新了线程级别的安全存储上下文
	 * 那就更新HttpSession级别的安全上下文的
	 */
	final class SaveToSessionResponseWrapper extends SaveContextOnUpdateOrErrorResponseWrapper {

		private final Log logger = HttpSessionSecurityContextRepository.this.logger;

		private final HttpServletRequest request;

		/**
		 * 在创建包装器的时候，是否存在HttpSession的标志位
		 * 存在即为true
		 */
		private final boolean httpSessionExistedAtStartOfRequest;

		/**
		 * 当前用户的安全上下文
		 */
		private final SecurityContext contextBeforeExecution;

		/**
		 * 在创建当前包装器的时候，就已经存在的认证对象
		 */
		private final Authentication authBeforeExecution;

		/**
		 * 是否已经更新过安全上下文了
		 */
		private boolean isSaveContextInvoked;

		/**
		 * Takes the parameters required to call <code>saveContext()</code> successfully
		 * in addition to the request and the response object we are wrapping.
		 * @param request the request object (used to obtain the session, if one exists).
		 * @param httpSessionExistedAtStartOfRequest indicates whether there was a session
		 * in place before the filter chain executed. If this is true, and the session is
		 * found to be null, this indicates that it was invalidated during the request and
		 * a new session will now be created.
		 * @param context the context before the filter chain executed. The context will
		 * only be stored if it or its contents changed during the request.
		 */
		SaveToSessionResponseWrapper(HttpServletResponse response, HttpServletRequest request,
				boolean httpSessionExistedAtStartOfRequest, SecurityContext context) {
			super(response, HttpSessionSecurityContextRepository.this.disableUrlRewriting);
			this.request = request;
			this.httpSessionExistedAtStartOfRequest = httpSessionExistedAtStartOfRequest;
			this.contextBeforeExecution = context;
			this.authBeforeExecution = context.getAuthentication();
		}

		/**
		 * 更新存储在HttpSession中的安全上下文
		 * 如果AuthenticationTrustResolver将当前用户识别为匿名用户，则不会存储上下文
		 * @param context 线程级别的安全上下文
		 */
		@Override
		protected void saveContext(SecurityContext context) {
			//首先获得认证对象
			final Authentication authentication = context.getAuthentication();
			HttpSession httpSession = this.request.getSession(false);
			String springSecurityContextKey = HttpSessionSecurityContextRepository.this.springSecurityContextKey;
			//如果没有认证对象或者是匿名用户
			if (authentication == null
					|| HttpSessionSecurityContextRepository.this.trustResolver.isAnonymous(authentication)) {

				//如果是匿名用户和空认证对象那么安全上下文其实已经没有任何意义，如果存在就删除它
				if (httpSession != null && this.authBeforeExecution != null) {
					//删除存储在HttpSession中的安全上下文
					httpSession.removeAttribute(springSecurityContextKey);
					this.isSaveContextInvoked = true;
				}
				if (this.logger.isDebugEnabled()) {
					if (authentication == null) {
						this.logger.debug("Did not store empty SecurityContext");
					}
					else {
						this.logger.debug("Did not store anonymous SecurityContext");
					}
				}
				return;
			}
			//如果为空就创建新的HttpSession
			httpSession = (httpSession != null) ? httpSession : createNewSessionIfAllowed(context, authentication);
			//如果HttpSession存在，存储当前的安全上下文
			//但仅当它在此线程中发生了变化
			if (httpSession != null) {
				//可能是一个新的会话，所以还要检查上下文属性
				if (contextChanged(context) || httpSession.getAttribute(springSecurityContextKey) == null) {
					httpSession.setAttribute(springSecurityContextKey, context);
					this.isSaveContextInvoked = true;
					if (this.logger.isDebugEnabled()) {
						this.logger.debug(LogMessage.format("Stored %s to HttpSession [%s]", context, httpSession));
					}
				}
			}
		}

		/**
		 * 是否和原来的安全上下文已经不一样了
		 * @param context
		 * @return
		 */
		private boolean contextChanged(SecurityContext context) {
			return this.isSaveContextInvoked || context != this.contextBeforeExecution
					|| context.getAuthentication() != this.authBeforeExecution;
		}

		/**
		 * 创建一个新HttpSession
		 * @param context
		 * @param authentication
		 * @return
		 */
		private HttpSession createNewSessionIfAllowed(SecurityContext context, Authentication authentication) {
			//判断是否是即时的认证对象
			if (isTransientAuthentication(authentication)) {
				return null;
			}
			//如果在创建包装类的时候存在HttpSession，那就不用创建新的了
			if (this.httpSessionExistedAtStartOfRequest) {
				this.logger.debug("HttpSession is now null, but was not null at start of request; "
						+ "session was invalidated, so do not create a new session");
				return null;
			}
			//如果不允许创建HttpSession
			if (!HttpSessionSecurityContextRepository.this.allowSessionCreation) {
				this.logger.debug("The HttpSession is currently null, and the "
						+ HttpSessionSecurityContextRepository.class.getSimpleName()
						+ " is prohibited from creating an HttpSession "
						+ "(because the allowSessionCreation property is false) - SecurityContext thus not "
						+ "stored for next request");
				return null;
			}

			//传入的安全上下文是空上下文，那么就没必要创建和放入HttpSession中了
			if (HttpSessionSecurityContextRepository.this.contextObject.equals(context)) {
				this.logger.debug(LogMessage.format(
						"HttpSession is null, but SecurityContext has not changed from "
								+ "default empty context %s so not creating HttpSession or storing SecurityContext",
						context));
				return null;
			}
			try {
				//创建新的HttpSession
				HttpSession session = this.request.getSession(true);
				this.logger.debug("Created HttpSession as SecurityContext is non-default");
				return session;
			}
			catch (IllegalStateException ex) {
				// Response must already be committed, therefore can't create a new
				// session
				this.logger.warn("Failed to create a session, as response has been committed. "
						+ "Unable to store SecurityContext.");
			}
			return null;
		}

	}

}

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

package org.springframework.security.access.expression.method;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.core.log.LogMessage;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.PermissionCacheOptimizer;
import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.parameters.DefaultSecurityParameterNameDiscoverer;
import org.springframework.util.Assert;

/**
 * 和 {@link org.springframework.security.access.prepost.PreFilter @PreFilter} 有关，作用是过滤集合或者数组中的数据
 * <p>
 * The standard implementation of {@code MethodSecurityExpressionHandler}.
 * <p>
 * A single instance should usually be shared amongst the beans that require expression
 * support.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultMethodSecurityExpressionHandler extends AbstractSecurityExpressionHandler<MethodInvocation>
		implements MethodSecurityExpressionHandler {

	protected final Log logger = LogFactory.getLog(getClass());

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private ParameterNameDiscoverer parameterNameDiscoverer = new DefaultSecurityParameterNameDiscoverer();

	private PermissionCacheOptimizer permissionCacheOptimizer = null;

	private String defaultRolePrefix = "ROLE_";

	public DefaultMethodSecurityExpressionHandler() {
	}

	/**
	 * Uses a {@link MethodSecurityEvaluationContext} as the <tt>EvaluationContext</tt>
	 * implementation.
	 */
	@Override
	public StandardEvaluationContext createEvaluationContextInternal(Authentication auth, MethodInvocation mi) {
		return new MethodSecurityEvaluationContext(auth, mi, getParameterNameDiscoverer());
	}

	/**
	 * Creates the root object for expression evaluation.
	 */
	@Override
	protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
			MethodInvocation invocation) {
		MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(authentication);
		root.setThis(invocation.getThis());
		root.setPermissionEvaluator(getPermissionEvaluator());
		root.setTrustResolver(getTrustResolver());
		root.setRoleHierarchy(getRoleHierarchy());
		root.setDefaultRolePrefix(getDefaultRolePrefix());
		return root;
	}

	/**
	 * 对参数中的数据进行过滤
	 */
	@Override
	public Object filter(Object filterTarget, Expression filterExpression, EvaluationContext ctx) {
		MethodSecurityExpressionOperations rootObject = (MethodSecurityExpressionOperations) ctx.getRootObject()
				.getValue();
		this.logger.debug(LogMessage.format("Filtering with expression: %s", filterExpression.getExpressionString()));
		if (filterTarget instanceof Collection) {
			return filterCollection((Collection<?>) filterTarget, filterExpression, ctx, rootObject);
		}
		if (filterTarget.getClass().isArray()) {
			return filterArray((Object[]) filterTarget, filterExpression, ctx, rootObject);
		}
		if (filterTarget instanceof Map) {
			return filterMap((Map<?, ?>) filterTarget, filterExpression, ctx, rootObject);
		}
		if (filterTarget instanceof Stream) {
			return filterStream((Stream<?>) filterTarget, filterExpression, ctx, rootObject);
		}
		throw new IllegalArgumentException(
				"Filter target must be a collection, array, map or stream type, but was " + filterTarget);
	}

	/**
	 * 过滤器集合中的数据
	 * @param filterTarget
	 * @param filterExpression
	 * @param ctx
	 * @param rootObject
	 * @param <T>
	 * @return
	 */
	private <T> Object filterCollection(Collection<T> filterTarget, Expression filterExpression, EvaluationContext ctx,
			MethodSecurityExpressionOperations rootObject) {
		this.logger.debug(LogMessage.format("Filtering collection with %s elements", filterTarget.size()));
		List<T> retain = new ArrayList<>(filterTarget.size());
		if (this.permissionCacheOptimizer != null) {
			this.permissionCacheOptimizer.cachePermissionsFor(rootObject.getAuthentication(), filterTarget);
		}
		for (T filterObject : filterTarget) {
			rootObject.setFilterObject(filterObject);
			if (ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
				retain.add(filterObject);
			}
		}
		this.logger.debug(LogMessage.format("Retaining elements: %s", retain));
		filterTarget.clear();
		filterTarget.addAll(retain);
		return filterTarget;
	}

	/**
	 * 过滤数组中的数据
	 * @param filterTarget
	 * @param filterExpression
	 * @param ctx
	 * @param rootObject
	 * @return
	 */
	private Object filterArray(Object[] filterTarget, Expression filterExpression, EvaluationContext ctx,
			MethodSecurityExpressionOperations rootObject) {
		List<Object> retain = new ArrayList<>(filterTarget.length);
		this.logger.debug(LogMessage.format("Filtering array with %s elements", filterTarget.length));
		if (this.permissionCacheOptimizer != null) {
			this.permissionCacheOptimizer.cachePermissionsFor(rootObject.getAuthentication(),
					Arrays.asList(filterTarget));
		}
		for (Object filterObject : filterTarget) {
			rootObject.setFilterObject(filterObject);
			if (ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
				retain.add(filterObject);
			}
		}
		this.logger.debug(LogMessage.format("Retaining elements: %s", retain));
		Object[] filtered = (Object[]) Array.newInstance(filterTarget.getClass().getComponentType(), retain.size());
		for (int i = 0; i < retain.size(); i++) {
			filtered[i] = retain.get(i);
		}
		return filtered;
	}

	/**
	 * 对Map进行过滤
	 * @param filterTarget
	 * @param filterExpression
	 * @param ctx
	 * @param rootObject
	 * @param <K>
	 * @param <V>
	 * @return
	 */
	private <K, V> Object filterMap(final Map<K, V> filterTarget, Expression filterExpression, EvaluationContext ctx,
			MethodSecurityExpressionOperations rootObject) {
		Map<K, V> retain = new LinkedHashMap<>(filterTarget.size());
		this.logger.debug(LogMessage.format("Filtering map with %s elements", filterTarget.size()));
		for (Map.Entry<K, V> filterObject : filterTarget.entrySet()) {
			rootObject.setFilterObject(filterObject);
			if (ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
				retain.put(filterObject.getKey(), filterObject.getValue());
			}
		}
		this.logger.debug(LogMessage.format("Retaining elements: %s", retain));
		filterTarget.clear();
		filterTarget.putAll(retain);
		return filterTarget;
	}

	/**
	 * 对流进行过滤
	 * @param filterTarget
	 * @param filterExpression
	 * @param ctx
	 * @param rootObject
	 * @return
	 */
	private Object filterStream(final Stream<?> filterTarget, Expression filterExpression, EvaluationContext ctx,
			MethodSecurityExpressionOperations rootObject) {
		return filterTarget.filter((filterObject) -> {
			rootObject.setFilterObject(filterObject);
			return ExpressionUtils.evaluateAsBoolean(filterExpression, ctx);
		}).onClose(filterTarget::close);
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

	/**
	 * @return The current {@link AuthenticationTrustResolver}
	 */
	protected AuthenticationTrustResolver getTrustResolver() {
		return this.trustResolver;
	}

	/**
	 * Sets the {@link ParameterNameDiscoverer} to use. The default is
	 * {@link DefaultSecurityParameterNameDiscoverer}.
	 * @param parameterNameDiscoverer
	 */
	public void setParameterNameDiscoverer(ParameterNameDiscoverer parameterNameDiscoverer) {
		this.parameterNameDiscoverer = parameterNameDiscoverer;
	}

	/**
	 * @return The current {@link ParameterNameDiscoverer}
	 */
	protected ParameterNameDiscoverer getParameterNameDiscoverer() {
		return this.parameterNameDiscoverer;
	}

	public void setPermissionCacheOptimizer(PermissionCacheOptimizer permissionCacheOptimizer) {
		this.permissionCacheOptimizer = permissionCacheOptimizer;
	}

	@Override
	public void setReturnObject(Object returnObject, EvaluationContext ctx) {
		((MethodSecurityExpressionOperations) ctx.getRootObject().getValue()).setReturnObject(returnObject);
	}

	/**
	 * <p>
	 * Sets the default prefix to be added to
	 * {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasAnyRole(String...)}
	 * or
	 * {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasRole(String)}.
	 * For example, if hasRole("ADMIN") or hasRole("ROLE_ADMIN") is passed in, then the
	 * role ROLE_ADMIN will be used when the defaultRolePrefix is "ROLE_" (default).
	 * </p>
	 *
	 * <p>
	 * If null or empty, then no default role prefix is used.
	 * </p>
	 * @param defaultRolePrefix the default prefix to add to roles. Default "ROLE_".
	 */
	public void setDefaultRolePrefix(String defaultRolePrefix) {
		this.defaultRolePrefix = defaultRolePrefix;
	}

	/**
	 * @return The default role prefix
	 */
	protected String getDefaultRolePrefix() {
		return this.defaultRolePrefix;
	}

}

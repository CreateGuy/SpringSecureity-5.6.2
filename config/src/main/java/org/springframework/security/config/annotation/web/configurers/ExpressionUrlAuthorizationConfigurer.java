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

package org.springframework.security.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * 添加基于SpEL表达式的URL的授权
 * At least
 * one {@link org.springframework.web.bind.annotation.RequestMapping} needs to be mapped
 * to {@link ConfigAttribute}'s for this {@link SecurityContextConfigurer} to have
 * meaning.
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}
 * </li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated to allow other
 * {@link org.springframework.security.config.annotation.SecurityConfigurer}'s to
 * customize:
 * <ul>
 * <li>{@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}
 * </li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * <ul>
 * <li>{@link AuthenticationTrustResolver} is optionally used to populate the
 * {@link DefaultWebSecurityExpressionHandler}</li>
 * </ul>
 *
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured
 * @author Rob Winch
 * @author Yanming Zhou
 * @since 3.2
 * @see org.springframework.security.config.annotation.web.builders.HttpSecurity#authorizeRequests()
 */
public final class ExpressionUrlAuthorizationConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractInterceptUrlConfigurer<ExpressionUrlAuthorizationConfigurer<H>, H> {

	/**
	 * 下面这几个都是Url的权限配置
	 * <p>都允许，都不允许，只有匿名用户，需要认证过，需要完整认证，记住我人认证</p>
	 */
	static final String permitAll = "permitAll";

	private static final String denyAll = "denyAll";

	private static final String anonymous = "anonymous";

	private static final String authenticated = "authenticated";

	private static final String fullyAuthenticated = "fullyAuthenticated";

	private static final String rememberMe = "rememberMe";

	/**
	 * 角色前缀
	 */
	private final String rolePrefix;

	/**
	 * 基于表达式的 Url注册中心
	 */
	private final ExpressionInterceptUrlRegistry REGISTRY;

	/**
	 * Web安全表达式处理器
	 */
	private SecurityExpressionHandler<FilterInvocation> expressionHandler;

	/**
	 * Creates a new instance
	 * @see HttpSecurity#authorizeRequests()
	 */
	public ExpressionUrlAuthorizationConfigurer(ApplicationContext context) {
		//从容器中获取角色前缀类
		String[] grantedAuthorityDefaultsBeanNames = context.getBeanNamesForType(GrantedAuthorityDefaults.class);
		//只有一个的时候才能自定义角色前缀，否则用默认的 ROLE_
		if (grantedAuthorityDefaultsBeanNames.length == 1) {
			GrantedAuthorityDefaults grantedAuthorityDefaults = context.getBean(grantedAuthorityDefaultsBeanNames[0],
					GrantedAuthorityDefaults.class);
			this.rolePrefix = grantedAuthorityDefaults.getRolePrefix();
		}
		else {
			this.rolePrefix = "ROLE_";
		}
		this.REGISTRY = new ExpressionInterceptUrlRegistry(context);
	}

	public ExpressionInterceptUrlRegistry getRegistry() {
		return this.REGISTRY;
	}

	/**
	 * 将已经配置了规则的请求匹配器，保存到响应的位置上
	 * @param requestMatchers
	 * @param configAttributes
	 */
	private void interceptUrl(Iterable<? extends RequestMatcher> requestMatchers,
			Collection<ConfigAttribute> configAttributes) {
		for (RequestMatcher requestMatcher : requestMatchers) {
			this.REGISTRY.addMapping(
					new AbstractConfigAttributeRequestMatcherRegistry.UrlMapping(requestMatcher, configAttributes));
		}
	}

	/**
	 * 获得访问访问决策投票器集合
	 * @param http the builder to use
	 * @return
	 */
	@Override
	@SuppressWarnings("rawtypes")
	List<AccessDecisionVoter<?>> getDecisionVoters(H http) {
		List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
		WebExpressionVoter expressionVoter = new WebExpressionVoter();
		expressionVoter.setExpressionHandler(getExpressionHandler(http));
		decisionVoters.add(expressionVoter);
		return decisionVoters;
	}

	/**
	 * 获得安全元数据
	 * @param http the builder to use
	 * @return
	 */
	@Override
	ExpressionBasedFilterInvocationSecurityMetadataSource createMetadataSource(H http) {
		//获得请求表达式和权限表达式的映射关系
		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = this.REGISTRY.createRequestMap();
		Assert.state(!requestMap.isEmpty(),
				"At least one mapping is required (i.e. authorizeRequests().anyRequest().authenticated())");
		return new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap, getExpressionHandler(http));
	}

	/**
	 * 获得Web安全表达式处理器
	 * @param http
	 * @return
	 */
	private SecurityExpressionHandler<FilterInvocation> getExpressionHandler(H http) {
		if (this.expressionHandler != null) {
			return this.expressionHandler;
		}
		DefaultWebSecurityExpressionHandler defaultHandler = new DefaultWebSecurityExpressionHandler();

		//设置认证对象分析器
		AuthenticationTrustResolver trustResolver = http.getSharedObject(AuthenticationTrustResolver.class);
		if (trustResolver != null) {
			defaultHandler.setTrustResolver(trustResolver);
		}
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		if (context != null) {
			//设置角色继承器
			String[] roleHiearchyBeanNames = context.getBeanNamesForType(RoleHierarchy.class);
			if (roleHiearchyBeanNames.length == 1) {
				defaultHandler.setRoleHierarchy(context.getBean(roleHiearchyBeanNames[0], RoleHierarchy.class));
			}

			//设置角色前缀
			String[] grantedAuthorityDefaultsBeanNames = context.getBeanNamesForType(GrantedAuthorityDefaults.class);
			if (grantedAuthorityDefaultsBeanNames.length == 1) {
				GrantedAuthorityDefaults grantedAuthorityDefaults = context
						.getBean(grantedAuthorityDefaultsBeanNames[0], GrantedAuthorityDefaults.class);
				defaultHandler.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
			}

			//设置权限评估器
			String[] permissionEvaluatorBeanNames = context.getBeanNamesForType(PermissionEvaluator.class);
			if (permissionEvaluatorBeanNames.length == 1) {
				PermissionEvaluator permissionEvaluator = context.getBean(permissionEvaluatorBeanNames[0],
						PermissionEvaluator.class);
				defaultHandler.setPermissionEvaluator(permissionEvaluator);
			}
		}
		this.expressionHandler = postProcess(defaultHandler);
		return this.expressionHandler;
	}

	/**
	 * 封装角色表达式，可以指定角色前缀
	 * @param rolePrefix
	 * @param authorities
	 * @return eg：hasRole('ROLE_admin')
	 */
	private static String hasAnyRole(String rolePrefix, String... authorities) {
		String anyAuthorities = StringUtils.arrayToDelimitedString(authorities, "','" + rolePrefix);
		return "hasAnyRole('" + rolePrefix + anyAuthorities + "')";
	}

	/**
	 * 封装角色表达式
	 * @param rolePrefix
	 * @param role
	 * @return eg：hasRole('ROLE_admin')
	 */
	private static String hasRole(String rolePrefix, String role) {
		Assert.notNull(role, "role cannot be null");
		Assert.isTrue(rolePrefix.isEmpty() || !role.startsWith(rolePrefix), () -> "role should not start with '"
				+ rolePrefix + "' since it is automatically inserted. Got '" + role + "'");
		return "hasRole('" + rolePrefix + role + "')";
	}

	/**
	 * 封装权限表达式，与角色的区别只在于有没有一个前缀
	 * @return eg：hasAuthority('admin')
	 */
	private static String hasAuthority(String authority) {
		return "hasAuthority('" + authority + "')";
	}

	/**
	 * 封装权限表达式，是有其中任意一个表达式就可以
	 * @return eg：hasAuthority('admin')
	 */
	private static String hasAnyAuthority(String... authorities) {
		String anyAuthorities = StringUtils.arrayToDelimitedString(authorities, "','");
		return "hasAnyAuthority('" + anyAuthorities + "')";
	}

	/**
	 * 封装ip地址表达式
	 * @param ipAddressExpression
	 * @return
	 */
	private static String hasIpAddress(String ipAddressExpression) {
		return "hasIpAddress('" + ipAddressExpression + "')";
	}

	/**
	 * 基于表达式的 Url注册中心
	 */
	public final class ExpressionInterceptUrlRegistry extends
			ExpressionUrlAuthorizationConfigurer<H>.AbstractInterceptUrlRegistry<ExpressionInterceptUrlRegistry, AuthorizedUrl> {

		private ExpressionInterceptUrlRegistry(ApplicationContext context) {
			setApplicationContext(context);
		}

		@Override
		public MvcMatchersAuthorizedUrl mvcMatchers(HttpMethod method, String... mvcPatterns) {
			return new MvcMatchersAuthorizedUrl(createMvcMatchers(method, mvcPatterns));
		}

		@Override
		public MvcMatchersAuthorizedUrl mvcMatchers(String... patterns) {
			return mvcMatchers(null, patterns);
		}

		@Override
		protected AuthorizedUrl chainRequestMatchersInternal(List<RequestMatcher> requestMatchers) {
			return new AuthorizedUrl(requestMatchers);
		}

		/**
		 * Allows customization of the {@link SecurityExpressionHandler} to be used. The
		 * default is {@link DefaultWebSecurityExpressionHandler}
		 * @param expressionHandler the {@link SecurityExpressionHandler} to be used
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization.
		 */
		public ExpressionInterceptUrlRegistry expressionHandler(
				SecurityExpressionHandler<FilterInvocation> expressionHandler) {
			ExpressionUrlAuthorizationConfigurer.this.expressionHandler = expressionHandler;
			return this;
		}

		/**
		 * Adds an {@link ObjectPostProcessor} for this class.
		 * @param objectPostProcessor
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customizations
		 */
		public ExpressionInterceptUrlRegistry withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
			addObjectPostProcessor(objectPostProcessor);
			return this;
		}

		public H and() {
			return ExpressionUrlAuthorizationConfigurer.this.and();
		}

	}

	/**
	 * 基于mvc的，保存请求匹配器的地方，方便为这些请求匹配器指定规则
	 */
	public final class MvcMatchersAuthorizedUrl extends AuthorizedUrl {

		/**
		 * Creates a new instance
		 * @param requestMatchers the {@link RequestMatcher} instances to map
		 */
		private MvcMatchersAuthorizedUrl(List<MvcRequestMatcher> requestMatchers) {
			super(requestMatchers);
		}

		public AuthorizedUrl servletPath(String servletPath) {
			for (MvcRequestMatcher matcher : (List<MvcRequestMatcher>) getMatchers()) {
				matcher.setServletPath(servletPath);
			}
			return this;
		}

	}

	/**
	 * 保存请求匹配器的地方，方便为这些请求匹配器指定规则
	 * <p>比如说，请求匹配器匹配成功/a的请求，然后这里可以配置需要什么角色或者认证方式了</p>
	 */
	public class AuthorizedUrl {

		private List<? extends RequestMatcher> requestMatchers;

		/**
		 * 是否否定之后的所有规则
		 */
		private boolean not;

		/**
		 * Creates a new instance
		 * @param requestMatchers the {@link RequestMatcher} instances to map
		 */
		AuthorizedUrl(List<? extends RequestMatcher> requestMatchers) {
			this.requestMatchers = requestMatchers;
		}

		protected List<? extends RequestMatcher> getMatchers() {
			return this.requestMatchers;
		}

		/**
		 * Negates the following expression.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public AuthorizedUrl not() {
			this.not = true;
			return this;
		}

		/**
		 * 指定当前请求匹配器匹配成功后，认证对象需要有这个角色
		 * @param role
		 * @return
		 */
		public ExpressionInterceptUrlRegistry hasRole(String role) {
			return access(ExpressionUrlAuthorizationConfigurer
					.hasRole(ExpressionUrlAuthorizationConfigurer.this.rolePrefix, role));
		}

		/**
		 * Shortcut for specifying URLs require any of a number of roles. If you do not
		 * want to have role prefix (default "ROLE_") automatically inserted see
		 * {@link #hasAnyAuthority(String...)}
		 * @param roles the roles to require (i.e. USER, ADMIN, etc). Note, it should not
		 * start with role prefix as this is automatically inserted.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry hasAnyRole(String... roles) {
			return access(ExpressionUrlAuthorizationConfigurer
					.hasAnyRole(ExpressionUrlAuthorizationConfigurer.this.rolePrefix, roles));
		}

		/**
		 * Specify that URLs require a particular authority.
		 * @param authority the authority to require (i.e. ROLE_USER, ROLE_ADMIN, etc).
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry hasAuthority(String authority) {
			return access(ExpressionUrlAuthorizationConfigurer.hasAuthority(authority));
		}

		/**
		 * Specify that URLs requires any of a number authorities.
		 * @param authorities the requests require at least one of the authorities (i.e.
		 * "ROLE_USER","ROLE_ADMIN" would mean either "ROLE_USER" or "ROLE_ADMIN" is
		 * required).
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry hasAnyAuthority(String... authorities) {
			return access(ExpressionUrlAuthorizationConfigurer.hasAnyAuthority(authorities));
		}

		/**
		 * Specify that URLs requires a specific IP Address or <a href=
		 * "https://forum.spring.io/showthread.php?102783-How-to-use-hasIpAddress&p=343971#post343971"
		 * >subnet</a>.
		 * @param ipaddressExpression the ipaddress (i.e. 192.168.1.79) or local subnet
		 * (i.e. 192.168.0/24)
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry hasIpAddress(String ipaddressExpression) {
			return access(ExpressionUrlAuthorizationConfigurer.hasIpAddress(ipaddressExpression));
		}

		/**
		 * Specify that URLs are allowed by anyone.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry permitAll() {
			return access(permitAll);
		}

		/**
		 * Specify that URLs are allowed by anonymous users.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry anonymous() {
			return access(anonymous);
		}

		/**
		 * Specify that URLs are allowed by users that have been remembered.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 * @see RememberMeConfigurer
		 */
		public ExpressionInterceptUrlRegistry rememberMe() {
			return access(rememberMe);
		}

		/**
		 * Specify that URLs are not allowed by anyone.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry denyAll() {
			return access(denyAll);
		}

		/**
		 * Specify that URLs are allowed by any authenticated user.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry authenticated() {
			return access(authenticated);
		}

		/**
		 * Specify that URLs are allowed by users who have authenticated and were not
		 * "remembered".
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 * @see RememberMeConfigurer
		 */
		public ExpressionInterceptUrlRegistry fullyAuthenticated() {
			return access(fullyAuthenticated);
		}

		/**
		 * 指定当前请求匹配器能够匹配成功的请求 的表达式
		 * @param attribute eg："hasRole('ROLE_USER')
		 * @return
		 */
		public ExpressionInterceptUrlRegistry access(String attribute) {
			//是否已经否定了规则
			if (this.not) {
				attribute = "!" + attribute;
			}
			interceptUrl(this.requestMatchers, SecurityConfig.createList(attribute));
			return ExpressionUrlAuthorizationConfigurer.this.REGISTRY;
		}

	}

}

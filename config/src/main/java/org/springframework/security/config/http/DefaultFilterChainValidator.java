/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.config.http;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.servlet.Filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * FilterChainProxy配置完成的验证器
 */
public class DefaultFilterChainValidator implements FilterChainProxy.FilterChainValidator {

	private final Log logger = LogFactory.getLog(getClass());

	@Override
	public void validate(FilterChainProxy fcp) {
		//检查所有的过滤器连
		for (SecurityFilterChain filterChain : fcp.getFilterChains()) {
			//检查安全拦截程序保护登录页面URL的常见错误
			checkLoginPageIsntProtected(fcp, filterChain.getFilters());
			//检查特定过滤器是否出现重复的
			checkFilterStack(filterChain.getFilters());
		}
		//检查过滤器链的顺序
		checkPathOrder(new ArrayList<>(fcp.getFilterChains()));
		//检查过滤器链的请求规则是否重复了
		checkForDuplicateMatchers(new ArrayList<>(fcp.getFilterChains()));
	}

	/**
	 * 检查过滤器链的顺序
	 * @param filterChains
	 */
	private void checkPathOrder(List<SecurityFilterChain> filterChains) {
		Iterator<SecurityFilterChain> chains = filterChains.iterator();
		while (chains.hasNext()) {
			RequestMatcher matcher = ((DefaultSecurityFilterChain) chains.next()).getRequestMatcher();
			//注意：Any代表任意请求都能匹配，那这一个过滤器链必须出现在最后一个位置，不然不合理
			if (AnyRequestMatcher.INSTANCE.equals(matcher) && chains.hasNext()) {
				throw new IllegalArgumentException("A universal match pattern ('/**') is defined "
						+ " before other patterns in the filter chain, causing them to be ignored. Please check the "
						+ "ordering in your <security:http> namespace or FilterChainProxy bean configuration");
			}
		}
	}

	/**
	 * 检查过滤器链的请求规则是否重复了
	 * @param chains
	 */
	private void checkForDuplicateMatchers(List<SecurityFilterChain> chains) {
		while (chains.size() > 1) {
			DefaultSecurityFilterChain chain = (DefaultSecurityFilterChain) chains.remove(0);
			for (SecurityFilterChain test : chains) {
				//注意：请求匹配器重写了equals方法
				//比如说AntPathRequestMatcher的equals方法就比较了路径，请求方式等等
				if (chain.getRequestMatcher().equals(((DefaultSecurityFilterChain) test).getRequestMatcher())) {
					throw new IllegalArgumentException("The FilterChainProxy contains two filter chains using the"
							+ " matcher " + chain.getRequestMatcher() + ". If you are using multiple <http> namespace "
							+ "elements, you must use a 'pattern' attribute to define the request patterns to which they apply.");
				}
			}
		}
	}

	@SuppressWarnings({ "unchecked" })
	private <F extends Filter> F getFilter(Class<F> type, List<Filter> filters) {
		for (Filter f : filters) {
			if (type.isAssignableFrom(f.getClass())) {
				return (F) f;
			}
		}
		return null;
	}

	/**
	 * 检查特定过滤器是否出现重复的
	 * <ul>
	 *     <li>
	 *         里面出现的过滤器出现多个根本没有意义
	 *     </li>
	 * </ul>
	 */
	private void checkFilterStack(List<Filter> filters) {
		checkForDuplicates(SecurityContextPersistenceFilter.class, filters);
		checkForDuplicates(UsernamePasswordAuthenticationFilter.class, filters);
		checkForDuplicates(SessionManagementFilter.class, filters);
		checkForDuplicates(BasicAuthenticationFilter.class, filters);
		checkForDuplicates(SecurityContextHolderAwareRequestFilter.class, filters);
		checkForDuplicates(JaasApiIntegrationFilter.class, filters);
		checkForDuplicates(ExceptionTranslationFilter.class, filters);
		checkForDuplicates(FilterSecurityInterceptor.class, filters);
	}

	/**
	 * 检查是否有相同类型的过滤器
	 * @param clazz
	 * @param filters
	 */
	private void checkForDuplicates(Class<? extends Filter> clazz, List<Filter> filters) {
		for (int i = 0; i < filters.size(); i++) {
			Filter f1 = filters.get(i);
			if (clazz.isAssignableFrom(f1.getClass())) {
				// Found the first one, check remaining for another
				for (int j = i + 1; j < filters.size(); j++) {
					Filter f2 = filters.get(j);
					if (clazz.isAssignableFrom(f2.getClass())) {
						this.logger.warn("Possible error: Filters at position " + i + " and " + j + " are both "
								+ "instances of " + clazz.getName());
						return;
					}
				}
			}
		}
	}

	/**
	 * 检查安全拦截程序保护登录页面URL的常见错误
	 * @param fcp
	 * @param filterStack
	 */
	private void checkLoginPageIsntProtected(FilterChainProxy fcp, List<Filter> filterStack) {
		//拿到处理异常的过滤器
		ExceptionTranslationFilter etf = getFilter(ExceptionTranslationFilter.class, filterStack);
		//判断身份认证入口点是否是跳转到登录页的
		if (etf == null || !(etf.getAuthenticationEntryPoint() instanceof LoginUrlAuthenticationEntryPoint)) {
			return;
		}
		String loginPage = ((LoginUrlAuthenticationEntryPoint) etf.getAuthenticationEntryPoint()).getLoginFormUrl();
		this.logger.info("Checking whether login URL '" + loginPage + "' is accessible with your configuration");
		FilterInvocation loginRequest = new FilterInvocation(loginPage, "POST");
		List<Filter> filters = null;
		try {
			filters = fcp.getFilters(loginPage);
		}
		catch (Exception ex) {
			// May happen legitimately if a filter-chain request matcher requires more
			// request data than that provided
			// by the dummy request used when creating the filter invocation.
			this.logger.info("Failed to obtain filter chain information for the login page. Unable to complete check.");
		}
		if (filters == null || filters.isEmpty()) {
			this.logger.debug("Filter chain is empty for the login page");
			return;
		}
		//判断是否有生成登录页的过滤器
		if (getFilter(DefaultLoginPageGeneratingFilter.class, filters) != null) {
			this.logger.debug("Default generated login page is in use");
			return;
		}

		//拿到用于权限判断的过滤器
		FilterSecurityInterceptor fsi = getFilter(FilterSecurityInterceptor.class, filters);
		//拿到安全元数据源
		FilterInvocationSecurityMetadataSource fids = fsi.getSecurityMetadataSource();
		//判断登录页是否需要权限
		Collection<ConfigAttribute> attributes = fids.getAttributes(loginRequest);
		if (attributes == null) {
			this.logger.debug("No access attributes defined for login page URL");
			//到这就说明登录页并没有限制权限，再判断是否拒绝访问公共接口
			if (fsi.isRejectPublicInvocations()) {
				this.logger.warn("FilterSecurityInterceptor is configured to reject public invocations."
						+ " Your login page may not be accessible.");
			}
			return;
		}
		AnonymousAuthenticationFilter anonPF = getFilter(AnonymousAuthenticationFilter.class, filters);
		if (anonPF == null) {
			//登录页面受筛选器链保护，但没有启用匿名身份认证。这几乎是一个错误
			this.logger.warn("The login page is being protected by the filter chain, but you don't appear to have"
					+ " anonymous authentication enabled. This is almost certainly an error.");
			return;
		}

		//使用提供的属性模拟匿名访问。
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken("key", anonPF.getPrincipal(),
				anonPF.getAuthorities());

		//进行身份认证
		try {
			fsi.getAccessDecisionManager().decide(token, loginRequest, attributes);
		}
		catch (AccessDeniedException ex) {
			this.logger.warn("Anonymous access to the login page doesn't appear to be enabled. "
					+ "This is almost certainly an error. Please check your configuration allows unauthenticated "
					+ "access to the configured login page. (Simulated access was rejected: " + ex + ")");
		}
		catch (Exception ex) {
			// May happen legitimately if a filter-chain request matcher requires more
			// request data than that provided
			// by the dummy request used when creating the filter invocation. See SEC-1878
			this.logger.info("Unable to check access to the login page to determine if anonymous access is allowed. "
					+ "This might be an error, but can happen under normal circumstances.", ex);
		}
	}

}

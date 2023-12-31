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

package org.springframework.security.web.access.intercept;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;

/**
 * 通过 {@link WebSecurityConfigurerAdapter} 配置的权限，在这进行校验
 * <li>通过注解配置的在 {@link org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor} 中负责校验</li>
 * <p>
 * The <code>SecurityMetadataSource</code> required by this security interceptor is of
 * type {@link FilterInvocationSecurityMetadataSource}.
 * <p>
 * Refer to {@link AbstractSecurityInterceptor} for details on the workflow.
 * </p>
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class FilterSecurityInterceptor extends AbstractSecurityInterceptor implements Filter {

	/**
	 * 用于表示请求是否已经执行过此过滤器了
	 */
	private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";

	/**
	 * 安全元数据
	 */
	private FilterInvocationSecurityMetadataSource securityMetadataSource;

	/**
	 * 是否跳过检查
	 */
	private boolean observeOncePerRequest = true;

	/**
	 * Not used (we rely on IoC container lifecycle services instead)
	 * @param arg0 ignored
	 *
	 */
	@Override
	public void init(FilterConfig arg0) {
	}

	/**
	 * Not used (we rely on IoC container lifecycle services instead)
	 */
	@Override
	public void destroy() {
	}

	/**
	 * Method that is actually called by the filter chain. Simply delegates to the
	 * {@link #invoke(FilterInvocation)} method.
	 * @param request the servlet request
	 * @param response the servlet response
	 * @param chain the filter chain
	 * @throws IOException if the filter chain fails
	 * @throws ServletException if the filter chain fails
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		invoke(new FilterInvocation(request, response, chain));
	}

	public FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
		return this.securityMetadataSource;
	}

	@Override
	public SecurityMetadataSource obtainSecurityMetadataSource() {
		return this.securityMetadataSource;
	}

	public void setSecurityMetadataSource(FilterInvocationSecurityMetadataSource newSource) {
		this.securityMetadataSource = newSource;
	}

	@Override
	public Class<?> getSecureObjectClass() {
		return FilterInvocation.class;
	}

	public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
		//确定是否跳过安全检查
		if (isApplied(filterInvocation) && this.observeOncePerRequest) {
			// filter already applied to this request and user wants us to observe
			// once-per-request handling, so don't re-do security checking
			filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
			return;
		}
		//判断此请求是否是第一次调用此过滤器
		if (filterInvocation.getRequest() != null && this.observeOncePerRequest) {
			//标记为已经执行过安全检查了
			filterInvocation.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
		}
		//执行调用前的权限判断
		InterceptorStatusToken token = super.beforeInvocation(filterInvocation);
		try {
			filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
		}
		finally {
			//是否需要将认证对象恢复到 判断权限之前
			super.finallyInvocation(token);
		}
		//执行调用后的权限判断
		super.afterInvocation(token, null);
	}

	/**
	 * 确定是否跳过安全检查
	 * @param filterInvocation
	 * @return
	 */
	private boolean isApplied(FilterInvocation filterInvocation) {
		return (filterInvocation.getRequest() != null)
				&& (filterInvocation.getRequest().getAttribute(FILTER_APPLIED) != null);
	}

	/**
	 * Indicates whether once-per-request handling will be observed. By default this is
	 * <code>true</code>, meaning the <code>FilterSecurityInterceptor</code> will only
	 * execute once-per-request. Sometimes users may wish it to execute more than once per
	 * request, such as when JSP forwards are being used and filter security is desired on
	 * each included fragment of the HTTP request.
	 * @return <code>true</code> (the default) if once-per-request is honoured, otherwise
	 * <code>false</code> if <code>FilterSecurityInterceptor</code> will enforce
	 * authorizations for each and every fragment of the HTTP request.
	 */
	public boolean isObserveOncePerRequest() {
		return this.observeOncePerRequest;
	}

	public void setObserveOncePerRequest(boolean observeOncePerRequest) {
		this.observeOncePerRequest = observeOncePerRequest;
	}

}

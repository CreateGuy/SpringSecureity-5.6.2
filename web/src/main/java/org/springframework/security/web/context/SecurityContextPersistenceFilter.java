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

package org.springframework.security.web.context;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

/**
 * 为了从HttpSession级别的安全上下文存储策略中读取安全上下文，然后放到线程级别的安全上下文策略中
 * 方便后面程序操作安全上下文
 */
public class SecurityContextPersistenceFilter extends GenericFilterBean {

	/**
	 * 确保过滤器器在每个请求中只执行一次的key
	 */
	static final String FILTER_APPLIED = "__spring_security_scpf_applied";

	/**
	 * HttpSession级别的安全上下文存储策略
	 */
	private SecurityContextRepository repo;

	/**
	 * 是否允许创建Session，是同步SessionManagementConfigurer中的session创建策略
	 */
	private boolean forceEagerSessionCreation = false;

	public SecurityContextPersistenceFilter() {
		this(new HttpSessionSecurityContextRepository());
	}

	public SecurityContextPersistenceFilter(SecurityContextRepository repo) {
		this.repo = repo;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//确保过滤器器在每个请求中只执行一次
		if (request.getAttribute(FILTER_APPLIED) != null) {
			chain.doFilter(request, response);
			return;
		}
		//标志本次请求已经执行过当前过滤器
		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
		//是否允许创建Session
		if (this.forceEagerSessionCreation) {
			HttpSession session = request.getSession();
			if (this.logger.isDebugEnabled() && session.isNew()) {
				this.logger.debug(LogMessage.format("Created session %s eagerly", session.getId()));
			}
		}
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
		//从HttpSession级别的安全上下文存储策略中尝试获取安全上下文
		SecurityContext contextBeforeChainExecution = this.repo.loadContext(holder);
		try {
			//设置到线程级别的安全上下文存储策略中
			//方便后续程序的操作
			SecurityContextHolder.setContext(contextBeforeChainExecution);
			if (contextBeforeChainExecution.getAuthentication() == null) {
				logger.debug("Set SecurityContextHolder to empty SecurityContext");
			}
			else {
				if (this.logger.isDebugEnabled()) {
					this.logger
							.debug(LogMessage.format("Set SecurityContextHolder to %s", contextBeforeChainExecution));
				}
			}
			chain.doFilter(holder.getRequest(), holder.getResponse());
		}
		finally {
			//这里是已经执行完Controller的代码

			//先拿到当前用户的线程级别的安全上下文
			SecurityContext contextAfterChainExecution = SecurityContextHolder.getContext();
			//清空
			SecurityContextHolder.clearContext();
			//由于用户的线程级别的安全上下文，可能被修改过
			//所有重新设置到HttpSession的线程级别的安全上下文策略中
			this.repo.saveContext(contextAfterChainExecution, holder.getRequest(), holder.getResponse());
			request.removeAttribute(FILTER_APPLIED);
			this.logger.debug("Cleared SecurityContextHolder to complete request");
		}
	}

	public void setForceEagerSessionCreation(boolean forceEagerSessionCreation) {
		this.forceEagerSessionCreation = forceEagerSessionCreation;
	}

}

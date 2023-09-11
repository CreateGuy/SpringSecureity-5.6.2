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

package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;


/**
 * 匿名认证过滤器
 * 判断是否存在认证对象，如果没有就创建一个
 */
public class AnonymousAuthenticationFilter extends GenericFilterBean implements InitializingBean {

	/**
	 * 认证信息详情源
	 * 主要是构建详细信息的，默认这个就是获取远程地址+SessionId的
	 */
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	/**
	 * 创建匿名认证对象所需的key
	 */
	private String key;

	/**
	 * 匿名认证对象的principal，默认是一个字符串
	 */
	private Object principal;

	/**
	 * 匿名认证对象的权限
	 */
	private List<GrantedAuthority> authorities;

	/**
	 * Creates a filter with a principal named "anonymousUser" and the single authority
	 * "ROLE_ANONYMOUS".
	 * @param key the key to identify tokens created by this filter
	 */
	public AnonymousAuthenticationFilter(String key) {
		this(key, "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	}

	/**
	 * @param key key the key to identify tokens created by this filter
	 * @param principal the principal which will be used to represent anonymous users
	 * @param authorities the authority list for anonymous users
	 */
	public AnonymousAuthenticationFilter(String key, Object principal, List<GrantedAuthority> authorities) {
		Assert.hasLength(key, "key cannot be null or empty");
		Assert.notNull(principal, "Anonymous authentication principal must be set");
		Assert.notNull(authorities, "Anonymous authorities must be set");
		this.key = key;
		this.principal = principal;
		this.authorities = authorities;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.hasLength(this.key,  "key must have length");
		Assert.notNull(this.principal, "Anonymous authentication principal must be set");
		Assert.notNull(this.authorities, "Anonymous authorities must be set");
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		//当前会话没有认证对象的时候，创建一个匿名认证对象
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			//创建匿名认证对象
			Authentication authentication = createAuthentication((HttpServletRequest) req);
			//创建安全上下文
			SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(authentication);
			//设置到线程级别的安全上下文策略中
			SecurityContextHolder.setContext(context);
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.of(() -> "Set SecurityContextHolder to "
						+ SecurityContextHolder.getContext().getAuthentication()));
			}
			else {
				this.logger.debug("Set SecurityContextHolder to anonymous SecurityContext");
			}
		}
		else {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.of(() -> "Did not set SecurityContextHolder since already authenticated "
						+ SecurityContextHolder.getContext().getAuthentication()));
			}
		}
		chain.doFilter(req, res);
	}

	/**
	 * 创建匿名认证对象
	 * @param request
	 * @return
	 */
	protected Authentication createAuthentication(HttpServletRequest request) {
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(this.key, this.principal,
				this.authorities);
		token.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return token;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public Object getPrincipal() {
		return this.principal;
	}

	public List<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

}

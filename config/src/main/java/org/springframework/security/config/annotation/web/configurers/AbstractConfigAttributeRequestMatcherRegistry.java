/*
 * Copyright 2002-2013 the original author or authors.
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

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * A base class for registering {@link RequestMatcher}'s. For example, it might allow for
 * specifying which {@link RequestMatcher} require a certain level of authorization.
 *
 * @param <C> The object that is returned or Chained after creating the RequestMatcher
 * @author Rob Winch
 * @since 3.2
 * @see ChannelSecurityConfigurer
 * @see UrlAuthorizationConfigurer
 * @see ExpressionUrlAuthorizationConfigurer
 */
public abstract class AbstractConfigAttributeRequestMatcherRegistry<C> extends AbstractRequestMatcherRegistry<C> {

	/**
	 * 已经指定了规则的请求匹配器
	 */
	private List<UrlMapping> urlMappings = new ArrayList<>();

	/**
	 * 还没指定规则的请求匹配器
	 */
	private List<RequestMatcher> unmappedMatchers;

	/**
	 * Gets the {@link UrlMapping} added by subclasses in
	 * {@link #chainRequestMatchers(java.util.List)}. May be empty.
	 * @return the {@link UrlMapping} added by subclasses in
	 * {@link #chainRequestMatchers(java.util.List)}
	 */
	final List<UrlMapping> getUrlMappings() {
		return this.urlMappings;
	}

	/**
	 * Adds a {@link UrlMapping} added by subclasses in
	 * {@link #chainRequestMatchers(java.util.List)} and resets the unmapped
	 * {@link RequestMatcher}'s.
	 * @param urlMapping {@link UrlMapping} the mapping to add
	 */
	final void addMapping(UrlMapping urlMapping) {
		this.unmappedMatchers = null;
		this.urlMappings.add(urlMapping);
	}

	/**
	 * Marks the {@link RequestMatcher}'s as unmapped and then calls
	 * {@link #chainRequestMatchersInternal(List)}.
	 * @param requestMatchers the {@link RequestMatcher} instances that were created
	 * @return the chained Object for the subclass which allows association of something
	 * else to the {@link RequestMatcher}
	 */
	@Override
	protected final C chainRequestMatchers(List<RequestMatcher> requestMatchers) {
		//标记为还未指定规则的请求匹配器
		this.unmappedMatchers = requestMatchers;
		//本质上就是将这些请求匹配器保存起来，通过返回类设置规则
		return chainRequestMatchersInternal(requestMatchers);
	}

	/**
	 * Subclasses should implement this method for returning the object that is chained to
	 * the creation of the {@link RequestMatcher} instances.
	 * @param requestMatchers the {@link RequestMatcher} instances that were created
	 * @return the chained Object for the subclass which allows association of something
	 * else to the {@link RequestMatcher}
	 */
	protected abstract C chainRequestMatchersInternal(List<RequestMatcher> requestMatchers);

	/**
	 * Adds a {@link UrlMapping} added by subclasses in
	 * {@link #chainRequestMatchers(java.util.List)} at a particular index.
	 * @param index the index to add a {@link UrlMapping}
	 * @param urlMapping {@link UrlMapping} the mapping to add
	 */
	final void addMapping(int index, UrlMapping urlMapping) {
		this.urlMappings.add(index, urlMapping);
	}


	/**
	 * 创建请求表达式和权限表达式的映射关系
	 * @return
	 */
	final LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> createRequestMap() {
		Assert.state(this.unmappedMatchers == null, () -> "An incomplete mapping was found for " + this.unmappedMatchers
				+ ". Try completing it with something like requestUrls().<something>.hasRole('USER')");
		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<>();
		for (UrlMapping mapping : getUrlMappings()) {
			RequestMatcher matcher = mapping.getRequestMatcher();
			Collection<ConfigAttribute> configAttrs = mapping.getConfigAttrs();
			requestMap.put(matcher, configAttrs);
		}
		return requestMap;
	}

	/**
	 * 请求匹配器 到 权限表达式 的映射
	 */
	static final class UrlMapping {

		private final RequestMatcher requestMatcher;

		/**
		 * 比如说保存的就是 hasRole('ROLE_admin')
		 */
		private final Collection<ConfigAttribute> configAttrs;

		UrlMapping(RequestMatcher requestMatcher, Collection<ConfigAttribute> configAttrs) {
			this.requestMatcher = requestMatcher;
			this.configAttrs = configAttrs;
		}

		RequestMatcher getRequestMatcher() {
			return this.requestMatcher;
		}

		Collection<ConfigAttribute> getConfigAttrs() {
			return this.configAttrs;
		}

	}

}

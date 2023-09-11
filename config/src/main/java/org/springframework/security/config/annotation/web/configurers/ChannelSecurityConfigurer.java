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

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.channel.ChannelProcessor;
import org.springframework.security.web.access.channel.InsecureChannelProcessor;
import org.springframework.security.web.access.channel.RetryWithHttpEntryPoint;
import org.springframework.security.web.access.channel.RetryWithHttpsEntryPoint;
import org.springframework.security.web.access.channel.SecureChannelProcessor;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * 为应用程序添加通道安全性(即需要HTTPS或HTTP)
 * 为了使配置类有用，至少应该将一个RequestMatcher映射到HTTP或HTTPS
 */
public final class ChannelSecurityConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<ChannelSecurityConfigurer<H>, H> {

	/**
	 * 通道处理过滤器
	 */
	private ChannelProcessingFilter channelFilter = new ChannelProcessingFilter();

	/**
	 * 请求匹配器和具体权限的映射关系
	 */
	private LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<>();

	/**
	 * 通道处理器
	 */
	private List<ChannelProcessor> channelProcessors;

	/**
	 * Url注册中心
	 */
	private final ChannelRequestMatcherRegistry REGISTRY;

	/**
	 * Creates a new instance
	 * @see HttpSecurity#requiresChannel()
	 */
	public ChannelSecurityConfigurer(ApplicationContext context) {
		this.REGISTRY = new ChannelRequestMatcherRegistry(context);
	}

	public ChannelRequestMatcherRegistry getRegistry() {
		return this.REGISTRY;
	}

	@Override
	public void configure(H http) {
		ChannelDecisionManagerImpl channelDecisionManager = new ChannelDecisionManagerImpl();
		//设置通道处理器
		channelDecisionManager.setChannelProcessors(getChannelProcessors(http));
		channelDecisionManager = postProcess(channelDecisionManager);
		//设置通道决策管理器
		this.channelFilter.setChannelDecisionManager(channelDecisionManager);

		//设置安全元数据源
		DefaultFilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource = new DefaultFilterInvocationSecurityMetadataSource(
				this.requestMap);
		this.channelFilter.setSecurityMetadataSource(filterInvocationSecurityMetadataSource);
		this.channelFilter = postProcess(this.channelFilter);
		http.addFilter(this.channelFilter);
	}

	/**
	 * 获得通道处理器
	 * @param http
	 * @return
	 */
	private List<ChannelProcessor> getChannelProcessors(H http) {
		if (this.channelProcessors != null) {
			return this.channelProcessors;
		}

		//创建安全通过处理器
		InsecureChannelProcessor insecureChannelProcessor = new InsecureChannelProcessor();
		SecureChannelProcessor secureChannelProcessor = new SecureChannelProcessor();


		PortMapper portMapper = http.getSharedObject(PortMapper.class);
		if (portMapper != null) {

			RetryWithHttpEntryPoint httpEntryPoint = new RetryWithHttpEntryPoint();
			httpEntryPoint.setPortMapper(portMapper);
			insecureChannelProcessor.setEntryPoint(httpEntryPoint);
			//创建不安全通过处理器
			RetryWithHttpsEntryPoint httpsEntryPoint = new RetryWithHttpsEntryPoint();
			httpsEntryPoint.setPortMapper(portMapper);
			secureChannelProcessor.setEntryPoint(httpsEntryPoint);
		}
		insecureChannelProcessor = postProcess(insecureChannelProcessor);
		secureChannelProcessor = postProcess(secureChannelProcessor);
		return Arrays.asList(insecureChannelProcessor, secureChannelProcessor);
	}

	/**
	 * 添加一个属性
	 * @param attribute
	 * @param matchers
	 * @return
	 */
	private ChannelRequestMatcherRegistry addAttribute(String attribute, List<? extends RequestMatcher> matchers) {
		for (RequestMatcher matcher : matchers) {
			Collection<ConfigAttribute> attrs = Arrays.asList(new SecurityConfig(attribute));
			this.requestMap.put(matcher, attrs);
		}
		return this.REGISTRY;
	}

	public final class ChannelRequestMatcherRegistry
			extends AbstractConfigAttributeRequestMatcherRegistry<RequiresChannelUrl> {

		private ChannelRequestMatcherRegistry(ApplicationContext context) {
			setApplicationContext(context);
		}

		@Override
		public MvcMatchersRequiresChannelUrl mvcMatchers(HttpMethod method, String... mvcPatterns) {
			List<MvcRequestMatcher> mvcMatchers = createMvcMatchers(method, mvcPatterns);
			return new MvcMatchersRequiresChannelUrl(mvcMatchers);
		}

		@Override
		public MvcMatchersRequiresChannelUrl mvcMatchers(String... patterns) {
			return mvcMatchers(null, patterns);
		}

		@Override
		protected RequiresChannelUrl chainRequestMatchersInternal(List<RequestMatcher> requestMatchers) {
			return new RequiresChannelUrl(requestMatchers);
		}

		/**
		 * Adds an {@link ObjectPostProcessor} for this class.
		 * @param objectPostProcessor
		 * @return the {@link ChannelSecurityConfigurer} for further customizations
		 */
		public ChannelRequestMatcherRegistry withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
			addObjectPostProcessor(objectPostProcessor);
			return this;
		}

		/**
		 * Sets the {@link ChannelProcessor} instances to use in
		 * {@link ChannelDecisionManagerImpl}
		 * @param channelProcessors
		 * @return the {@link ChannelSecurityConfigurer} for further customizations
		 */
		public ChannelRequestMatcherRegistry channelProcessors(List<ChannelProcessor> channelProcessors) {
			ChannelSecurityConfigurer.this.channelProcessors = channelProcessors;
			return this;
		}

		/**
		 * Return the {@link SecurityBuilder} when done using the
		 * {@link SecurityConfigurer}. This is useful for method chaining.
		 * @return the type of {@link HttpSecurityBuilder} that is being configured
		 */
		public H and() {
			return ChannelSecurityConfigurer.this.and();
		}

	}

	public final class MvcMatchersRequiresChannelUrl extends RequiresChannelUrl {

		private MvcMatchersRequiresChannelUrl(List<MvcRequestMatcher> matchers) {
			super(matchers);
		}

		public RequiresChannelUrl servletPath(String servletPath) {
			for (RequestMatcher matcher : this.requestMatchers) {
				((MvcRequestMatcher) matcher).setServletPath(servletPath);
			}
			return this;
		}

	}

	public class RequiresChannelUrl {

		protected List<? extends RequestMatcher> requestMatchers;

		RequiresChannelUrl(List<? extends RequestMatcher> requestMatchers) {
			this.requestMatchers = requestMatchers;
		}

		public ChannelRequestMatcherRegistry requiresSecure() {
			return requires("REQUIRES_SECURE_CHANNEL");
		}

		public ChannelRequestMatcherRegistry requiresInsecure() {
			return requires("REQUIRES_INSECURE_CHANNEL");
		}

		public ChannelRequestMatcherRegistry requires(String attribute) {
			return addAttribute(attribute, this.requestMatchers);
		}

	}

}

/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.configuration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

/**
 * 全局认证管理器的配置类
 * 是通过SecurityAutoConfiguration->@Import(WebSecurityEnablerConfiguration.class)
 * ->@EnableWebSecurity->@EnableGlobalAuthentication->@Import(AuthenticationConfiguration.class)才有的
 */
@Configuration(proxyBeanMethods = false)
// 导入了AutowireBeanFactoryObjectPostProcessor
@Import(ObjectPostProcessorConfiguration.class)
public class AuthenticationConfiguration {

	private AtomicBoolean buildingAuthenticationManager = new AtomicBoolean();

	private ApplicationContext applicationContext;

	/**
	 * 全局认证管理器
	 */
	private AuthenticationManager authenticationManager;

	/**
	 * 是否初始化过认证管理器
	 */
	private boolean authenticationManagerInitialized;

	/**
	 * 这个集合也是对全局认证管理器的参数的配置
	 * 默认有三个，也是由当前类的@Bean方法进行注册的
	 * 	{@link EnableGlobalAuthenticationAutowiredConfigurer}
	 * 	{@link org.springframework.security.config.annotation.authentication.configuration.InitializeAuthenticationProviderBeanManagerConfigurer.InitializeAuthenticationProviderManagerConfigurer}
	 *  {@link org.springframework.security.config.annotation.authentication.configuration.InitializeUserDetailsBeanManagerConfigurer.InitializeUserDetailsManagerConfigurer}
	 */
	private List<GlobalAuthenticationConfigurerAdapter> globalAuthConfigurers = Collections.emptyList();

	/**
	 * 默认只有{@link org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor}
	 */
	private ObjectPostProcessor<Object> objectPostProcessor;

	/**
	 * 往容器中注册一个全局认证管理器构建器
	 * @param objectPostProcessor 默认就是{@link org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessor}
	 * @param context
	 * @return
	 */
	@Bean
	public AuthenticationManagerBuilder authenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor,
			ApplicationContext context) {
		//是一个懒加载机制的，只有用到才会真正创建
		LazyPasswordEncoder defaultPasswordEncoder = new LazyPasswordEncoder(context);
		//获取认证事件推送器
		AuthenticationEventPublisher authenticationEventPublisher = getBeanOrNull(context,
				AuthenticationEventPublisher.class);
		DefaultPasswordEncoderAuthenticationManagerBuilder result = new DefaultPasswordEncoderAuthenticationManagerBuilder(
				objectPostProcessor, defaultPasswordEncoder);
		if (authenticationEventPublisher != null) {
			result.authenticationEventPublisher(authenticationEventPublisher);
		}
		return result;
	}

	@Bean
	public static GlobalAuthenticationConfigurerAdapter enableGlobalAuthenticationAutowiredConfigurer(
			ApplicationContext context) {
		return new EnableGlobalAuthenticationAutowiredConfigurer(context);
	}

	@Bean
	public static InitializeUserDetailsBeanManagerConfigurer initializeUserDetailsBeanManagerConfigurer(
			ApplicationContext context) {
		return new InitializeUserDetailsBeanManagerConfigurer(context);
	}

	@Bean
	public static InitializeAuthenticationProviderBeanManagerConfigurer initializeAuthenticationProviderBeanManagerConfigurer(
			ApplicationContext context) {
		return new InitializeAuthenticationProviderBeanManagerConfigurer(context);
	}

	public AuthenticationManager getAuthenticationManager() throws Exception {
		if (this.authenticationManagerInitialized) {
			return this.authenticationManager;
		}
		//这个全局认证管理器是当前类的@Bean方法创建的
		AuthenticationManagerBuilder authBuilder = this.applicationContext.getBean(AuthenticationManagerBuilder.class);
		//说是为了防止在初始化AuthenticationManager时发生无限递归
		//要到这的条件：必须没有初始化，而且buildingAuthenticationManager为true
		//而buildingAuthenticationManager为true的时候必须要是第二次进入当前方法，第二次应该已经为初始化成功了呀？？，没懂
		if (this.buildingAuthenticationManager.getAndSet(true)) {
			return new AuthenticationManagerDelegator(authBuilder);
		}
		//将配置类加入到authBuilder中去
		for (GlobalAuthenticationConfigurerAdapter config : this.globalAuthConfigurers) {
			authBuilder.apply(config);
		}
		//重点：开始构建全局认证管理器
		this.authenticationManager = authBuilder.build();
		//如果没有构建成功
		if (this.authenticationManager == null) {
			//尝试从容器中获得
			this.authenticationManager = getAuthenticationManagerBean();
		}
		//标志位已经初始化完毕
		this.authenticationManagerInitialized = true;
		return this.authenticationManager;
	}

	@Autowired(required = false)
	public void setGlobalAuthenticationConfigurers(List<GlobalAuthenticationConfigurerAdapter> configurers) {
		configurers.sort(AnnotationAwareOrderComparator.INSTANCE);
		this.globalAuthConfigurers = configurers;
	}

	@Autowired
	public void setApplicationContext(ApplicationContext applicationContext) {
		this.applicationContext = applicationContext;
	}

	@Autowired
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	@SuppressWarnings("unchecked")
	private <T> T lazyBean(Class<T> interfaceName) {
		LazyInitTargetSource lazyTargetSource = new LazyInitTargetSource();
		String[] beanNamesForType = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(this.applicationContext,
				interfaceName);
		if (beanNamesForType.length == 0) {
			return null;
		}
		String beanName = getBeanName(interfaceName, beanNamesForType);
		lazyTargetSource.setTargetBeanName(beanName);
		lazyTargetSource.setBeanFactory(this.applicationContext);
		ProxyFactoryBean proxyFactory = new ProxyFactoryBean();
		proxyFactory = this.objectPostProcessor.postProcess(proxyFactory);
		proxyFactory.setTargetSource(lazyTargetSource);
		return (T) proxyFactory.getObject();
	}

	private <T> String getBeanName(Class<T> interfaceName, String[] beanNamesForType) {
		if (beanNamesForType.length == 1) {
			return beanNamesForType[0];
		}
		List<String> primaryBeanNames = getPrimaryBeanNames(beanNamesForType);
		Assert.isTrue(primaryBeanNames.size() != 0, () -> "Found " + beanNamesForType.length + " beans for type "
				+ interfaceName + ", but none marked as primary");
		Assert.isTrue(primaryBeanNames.size() == 1,
				() -> "Found " + primaryBeanNames.size() + " beans for type " + interfaceName + " marked as primary");
		return primaryBeanNames.get(0);
	}

	private List<String> getPrimaryBeanNames(String[] beanNamesForType) {
		List<String> list = new ArrayList<>();
		if (!(this.applicationContext instanceof ConfigurableApplicationContext)) {
			return Collections.emptyList();
		}
		for (String beanName : beanNamesForType) {
			if (((ConfigurableApplicationContext) this.applicationContext).getBeanFactory().getBeanDefinition(beanName)
					.isPrimary()) {
				list.add(beanName);
			}
		}
		return list;
	}

	private AuthenticationManager getAuthenticationManagerBean() {
		return lazyBean(AuthenticationManager.class);
	}

	private static <T> T getBeanOrNull(ApplicationContext applicationContext, Class<T> type) {
		try {
			return applicationContext.getBean(type);
		}
		catch (NoSuchBeanDefinitionException notFound) {
			return null;
		}
	}

	private static class EnableGlobalAuthenticationAutowiredConfigurer extends GlobalAuthenticationConfigurerAdapter {

		private final ApplicationContext context;

		private static final Log logger = LogFactory.getLog(EnableGlobalAuthenticationAutowiredConfigurer.class);

		EnableGlobalAuthenticationAutowiredConfigurer(ApplicationContext context) {
			this.context = context;
		}

		/**
		 * 拿到容器中使用了@EnableGlobalAuthentication注解的bean，然后什么都没有干？？，搞不懂
		 * @param auth
		 */
		@Override
		public void init(AuthenticationManagerBuilder auth) {
			Map<String, Object> beansWithAnnotation = this.context
					.getBeansWithAnnotation(EnableGlobalAuthentication.class);
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Eagerly initializing %s", beansWithAnnotation));
			}
		}

	}

	/**
	 * 防止在初始化认证管理器时发生无限递归
	 */
	static final class AuthenticationManagerDelegator implements AuthenticationManager {

		private AuthenticationManagerBuilder delegateBuilder;

		private AuthenticationManager delegate;

		private final Object delegateMonitor = new Object();

		AuthenticationManagerDelegator(AuthenticationManagerBuilder delegateBuilder) {
			Assert.notNull(delegateBuilder, "delegateBuilder cannot be null");
			this.delegateBuilder = delegateBuilder;
		}

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			if (this.delegate != null) {
				return this.delegate.authenticate(authentication);
			}
			synchronized (this.delegateMonitor) {
				if (this.delegate == null) {
					this.delegate = this.delegateBuilder.getObject();
					this.delegateBuilder = null;
				}
			}
			return this.delegate.authenticate(authentication);
		}

		@Override
		public String toString() {
			return "AuthenticationManagerDelegator [delegate=" + this.delegate + "]";
		}

	}

	/**
	 * 是SpringSecurity创建的全局认证管理器，还携带了密码编码器
	 */
	static class DefaultPasswordEncoderAuthenticationManagerBuilder extends AuthenticationManagerBuilder {

		private PasswordEncoder defaultPasswordEncoder;

		/**
		 * Creates a new instance
		 * @param objectPostProcessor the {@link ObjectPostProcessor} instance to use.
		 */
		DefaultPasswordEncoderAuthenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor,
				PasswordEncoder defaultPasswordEncoder) {
			super(objectPostProcessor);
			this.defaultPasswordEncoder = defaultPasswordEncoder;
		}

		@Override
		public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
				throws Exception {
			return super.inMemoryAuthentication().passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication() throws Exception {
			return super.jdbcAuthentication().passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder, T> userDetailsService(
				T userDetailsService) throws Exception {
			return super.userDetailsService(userDetailsService).passwordEncoder(this.defaultPasswordEncoder);
		}

	}

	/**
	 * 是SpringSecurity创建的全局认证管理器的时候，创建的懒加载机制的密码编码器
	 */
	static class LazyPasswordEncoder implements PasswordEncoder {

		private ApplicationContext applicationContext;

		private PasswordEncoder passwordEncoder;

		LazyPasswordEncoder(ApplicationContext applicationContext) {
			this.applicationContext = applicationContext;
		}

		@Override
		public String encode(CharSequence rawPassword) {
			return getPasswordEncoder().encode(rawPassword);
		}

		@Override
		public boolean matches(CharSequence rawPassword, String encodedPassword) {
			return getPasswordEncoder().matches(rawPassword, encodedPassword);
		}

		@Override
		public boolean upgradeEncoding(String encodedPassword) {
			return getPasswordEncoder().upgradeEncoding(encodedPassword);
		}

		private PasswordEncoder getPasswordEncoder() {
			if (this.passwordEncoder != null) {
				return this.passwordEncoder;
			}
			PasswordEncoder passwordEncoder = getBeanOrNull(this.applicationContext, PasswordEncoder.class);
			if (passwordEncoder == null) {
				passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
			}
			this.passwordEncoder = passwordEncoder;
			return passwordEncoder;
		}

		@Override
		public String toString() {
			return getPasswordEncoder().toString();
		}

	}

}

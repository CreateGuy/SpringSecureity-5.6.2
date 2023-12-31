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

package org.springframework.security.config.annotation.method.configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.aopalliance.intercept.MethodInterceptor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AfterInvocationProvider;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource;
import org.springframework.security.access.annotation.Jsr250Voter;
import org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.ExpressionBasedPostInvocationAdvice;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.intercept.AfterInvocationManager;
import org.springframework.security.access.intercept.AfterInvocationProviderManager;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.intercept.aspectj.AspectJMethodSecurityInterceptor;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PostInvocationAdviceProvider;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdvice;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.util.Assert;

/**
 * 提供权限注解的一些基本Bean
 * @since 3.2
 * @see EnableGlobalMethodSecurity
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
public class GlobalMethodSecurityConfiguration implements ImportAware, SmartInitializingSingleton, BeanFactoryAware {

	private static final Log logger = LogFactory.getLog(GlobalMethodSecurityConfiguration.class);

	/**
	 * 默认就是 {@link org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessor AutowireBeanFactoryObjectPostProcessor}
	 */
	private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {

		@Override
		public <T> T postProcess(T object) {
			throw new IllegalStateException(ObjectPostProcessor.class.getName()
					+ " is a required bean. Ensure you have used @" + EnableGlobalMethodSecurity.class.getName());
		}

	};

	private DefaultMethodSecurityExpressionHandler defaultMethodExpressionHandler = new DefaultMethodSecurityExpressionHandler();

	/**
	 * 认证管理器
	 */
	private AuthenticationManager authenticationManager;

	/**
	 * 认证管理器构建器
	 */
	private AuthenticationManagerBuilder auth;

	/**
	 * 是否使用容器中的认证管理器，还是使用上面的认证管理器构建器构建出来的
	 * <ul>如果没有重写configure方法，那么就为True</ul>
	 */
	private boolean disableAuthenticationRegistry;

	/**
	 * 导入类上关于 {@link EnableGlobalMethodSecurity @EnableGlobalMethodSecurity} 的属性
	 */
	private AnnotationAttributes enableMethodSecurity;

	private BeanFactory context;

	private MethodSecurityExpressionHandler expressionHandler;

	/**
	 * 最终在Cglib的CglibAopProxy中的拦截器
	 */
	private MethodSecurityInterceptor methodSecurityInterceptor;

	/**
	 * 创建 {@link MethodSecurityInterceptor}
	 */
	@Bean
	public MethodInterceptor methodSecurityInterceptor(MethodSecurityMetadataSource methodSecurityMetadataSource) {
		this.methodSecurityInterceptor = isAspectJ() ? new AspectJMethodSecurityInterceptor()
				: new MethodSecurityInterceptor();
		//设置访问决策管理器
		this.methodSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
		//设置执行后管理器
		this.methodSecurityInterceptor.setAfterInvocationManager(afterInvocationManager());
		//设置安全元数据源
		this.methodSecurityInterceptor.setSecurityMetadataSource(methodSecurityMetadataSource);
		RunAsManager runAsManager = runAsManager();
		if (runAsManager != null) {
			this.methodSecurityInterceptor.setRunAsManager(runAsManager);
		}
		return this.methodSecurityInterceptor;
	}

	@Override
	public void afterSingletonsInstantiated() {
		try {
			// 初始化 MethodSecurityInterceptor
			initializeMethodSecurityInterceptor();
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}

		// 设置权限评估器
		PermissionEvaluator permissionEvaluator = getSingleBeanOrNull(PermissionEvaluator.class);
		if (permissionEvaluator != null) {
			this.defaultMethodExpressionHandler.setPermissionEvaluator(permissionEvaluator);
		}

		// 设置角色继承器
		RoleHierarchy roleHierarchy = getSingleBeanOrNull(RoleHierarchy.class);
		if (roleHierarchy != null) {
			this.defaultMethodExpressionHandler.setRoleHierarchy(roleHierarchy);
		}

		// 设置认证对象解析器
		AuthenticationTrustResolver trustResolver = getSingleBeanOrNull(AuthenticationTrustResolver.class);
		if (trustResolver != null) {
			this.defaultMethodExpressionHandler.setTrustResolver(trustResolver);
		}

		// 设置角色默认前缀
		GrantedAuthorityDefaults grantedAuthorityDefaults = getSingleBeanOrNull(GrantedAuthorityDefaults.class);
		if (grantedAuthorityDefaults != null) {
			this.defaultMethodExpressionHandler.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
		}

		this.defaultMethodExpressionHandler = this.objectPostProcessor.postProcess(this.defaultMethodExpressionHandler);
	}

	/**
	 * 获得容器中的指定Bean
	 * @param type
	 * @param <T>
	 * @return
	 */
	private <T> T getSingleBeanOrNull(Class<T> type) {
		try {
			return this.context.getBean(type);
		}
		catch (NoSuchBeanDefinitionException ex) {
		}
		return null;
	}

	/**
	 * 初始化 {@link MethodSecurityInterceptor}
	 * @throws Exception
	 */
	private void initializeMethodSecurityInterceptor() throws Exception {
		if (this.methodSecurityInterceptor == null) {
			return;
		}
		// 设置认证管理器
		this.methodSecurityInterceptor.setAuthenticationManager(authenticationManager());
	}

	/**
	 * 创建 {@link AfterInvocationManager}
	 * <li>这个是为了在方法执行后，在继续操作，比如说 {@link org.springframework.security.access.prepost.PostAuthorize @PostAuthorize}</li>
	 * @return
	 */
	protected AfterInvocationManager afterInvocationManager() {
		if (prePostEnabled()) {
			AfterInvocationProviderManager invocationProviderManager = new AfterInvocationProviderManager();
			ExpressionBasedPostInvocationAdvice postAdvice = new ExpressionBasedPostInvocationAdvice(
					getExpressionHandler());
			PostInvocationAdviceProvider postInvocationAdviceProvider = new PostInvocationAdviceProvider(postAdvice);
			List<AfterInvocationProvider> afterInvocationProviders = new ArrayList<>();
			afterInvocationProviders.add(postInvocationAdviceProvider);
			invocationProviderManager.setProviders(afterInvocationProviders);
			return invocationProviderManager;
		}
		return null;
	}

	/**
	 * Provide a custom {@link RunAsManager} for the default implementation of
	 * {@link #methodSecurityInterceptor(MethodSecurityMetadataSource)}. The default is
	 * null.
	 * @return the {@link RunAsManager} to use
	 */
	protected RunAsManager runAsManager() {
		return null;
	}

	/**
	 * 创建访问决策管理器
	 */
	protected AccessDecisionManager accessDecisionManager() {
		List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
		// 开启了prePost的权限注解，创建对应的访问决策投票器
		if (prePostEnabled()) {
			ExpressionBasedPreInvocationAdvice expressionAdvice = new ExpressionBasedPreInvocationAdvice();
			expressionAdvice.setExpressionHandler(getExpressionHandler());
			decisionVoters.add(new PreInvocationAuthorizationAdviceVoter(expressionAdvice));
		}

		// 开启了jsr250的权限注解，创建对应的访问决策投票器
		if (jsr250Enabled()) {
			decisionVoters.add(new Jsr250Voter());
		}
		RoleVoter roleVoter = new RoleVoter();
		// 获得角色前缀
		GrantedAuthorityDefaults grantedAuthorityDefaults = getSingleBeanOrNull(GrantedAuthorityDefaults.class);
		if (grantedAuthorityDefaults != null) {
			roleVoter.setRolePrefix(grantedAuthorityDefaults.getRolePrefix());
		}

		// 有任何一个角色匹配就投同意票
		decisionVoters.add(roleVoter);

		// 根据认证方式投票
		decisionVoters.add(new AuthenticatedVoter());
		return new AffirmativeBased(decisionVoters);
	}

	/**
	 * Provide a {@link MethodSecurityExpressionHandler} that is registered with the
	 * {@link ExpressionBasedPreInvocationAdvice}. The default is
	 * {@link DefaultMethodSecurityExpressionHandler} which optionally will Autowire an
	 * {@link AuthenticationTrustResolver}.
	 *
	 * <p>
	 * Subclasses may override this method to provide a custom
	 * {@link MethodSecurityExpressionHandler}
	 * </p>
	 * @return the {@link MethodSecurityExpressionHandler} to use
	 */
	protected MethodSecurityExpressionHandler createExpressionHandler() {
		return this.defaultMethodExpressionHandler;
	}

	/**
	 * Gets the {@link MethodSecurityExpressionHandler} or creates it using
	 * {@link #expressionHandler}.
	 * @return a non {@code null} {@link MethodSecurityExpressionHandler}
	 */
	protected final MethodSecurityExpressionHandler getExpressionHandler() {
		if (this.expressionHandler == null) {
			this.expressionHandler = createExpressionHandler();
		}
		return this.expressionHandler;
	}

	/**
	 * 自定义安全元数据源
	 */
	protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
		return null;
	}

	/**
	 * 创建认证管理器
	 */
	protected AuthenticationManager authenticationManager() throws Exception {
		if (this.authenticationManager == null) {
			DefaultAuthenticationEventPublisher eventPublisher = this.objectPostProcessor
					.postProcess(new DefaultAuthenticationEventPublisher());
			this.auth = new AuthenticationManagerBuilder(this.objectPostProcessor);
			this.auth.authenticationEventPublisher(eventPublisher);
			configure(this.auth);

			// 是使用容器中的还是用构建起创建出来的
			this.authenticationManager = (this.disableAuthenticationRegistry)
					? getAuthenticationConfiguration().getAuthenticationManager() : this.auth.build();
		}
		return this.authenticationManager;
	}

	/**
	 * 操作 {@link AuthenticationManagerBuilder} 的回调方法
	 */
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		this.disableAuthenticationRegistry = true;
	}

	/**
	 * 注册安全元数据源
	 */
	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	public MethodSecurityMetadataSource methodSecurityMetadataSource() {
		List<MethodSecurityMetadataSource> sources = new ArrayList<>();
		ExpressionBasedAnnotationAttributeFactory attributeFactory = new ExpressionBasedAnnotationAttributeFactory(
				getExpressionHandler());

		// 自定义安全元数据源
		MethodSecurityMetadataSource customMethodSecurityMetadataSource = customMethodSecurityMetadataSource();
		if (customMethodSecurityMetadataSource != null) {
			sources.add(customMethodSecurityMetadataSource);
		}
		boolean hasCustom = customMethodSecurityMetadataSource != null;

		// 是否开启了下面三种类型的注解
		boolean isPrePostEnabled = prePostEnabled();
		boolean isSecuredEnabled = securedEnabled();
		boolean isJsr250Enabled = jsr250Enabled();
		Assert.state(isPrePostEnabled || isSecuredEnabled || isJsr250Enabled || hasCustom,
				"In the composition of all global method configuration, "
						+ "no annotation support was actually activated");

		// 尝试添加下面三种安全元数据源
		if (isPrePostEnabled) {
			sources.add(new PrePostAnnotationSecurityMetadataSource(attributeFactory));
		}
		if (isSecuredEnabled) {
			sources.add(new SecuredAnnotationSecurityMetadataSource());
		}
		if (isJsr250Enabled) {
			GrantedAuthorityDefaults grantedAuthorityDefaults = getSingleBeanOrNull(GrantedAuthorityDefaults.class);
			Jsr250MethodSecurityMetadataSource jsr250MethodSecurityMetadataSource = this.context
					.getBean(Jsr250MethodSecurityMetadataSource.class);
			// 设置角色前缀
			if (grantedAuthorityDefaults != null) {
				jsr250MethodSecurityMetadataSource.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
			}
			sources.add(jsr250MethodSecurityMetadataSource);
		}
		return new DelegatingMethodSecurityMetadataSource(sources);
	}

	/**
	 * Creates the {@link PreInvocationAuthorizationAdvice} to be used. The default is
	 * {@link ExpressionBasedPreInvocationAdvice}.
	 * @return the {@link PreInvocationAuthorizationAdvice}
	 */
	@Bean
	public PreInvocationAuthorizationAdvice preInvocationAuthorizationAdvice() {
		ExpressionBasedPreInvocationAdvice preInvocationAdvice = new ExpressionBasedPreInvocationAdvice();
		preInvocationAdvice.setExpressionHandler(getExpressionHandler());
		return preInvocationAdvice;
	}

	/**
	 * 设置导入类上的 {@link EnableGlobalMethodSecurity @EnableGlobalMethodSecurity} 信息
	 */
	@Override
	public final void setImportMetadata(AnnotationMetadata importMetadata) {
		Map<String, Object> annotationAttributes = importMetadata
				.getAnnotationAttributes(EnableGlobalMethodSecurity.class.getName());
		this.enableMethodSecurity = AnnotationAttributes.fromMap(annotationAttributes);
	}

	/**
	 * 是由 {@link org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration ObjectPostProcessorConfiguration} 导入容器的 {@link org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessor AutowireBeanFactoryObjectPostProcessor}
	 * @param objectPostProcessor
	 */
	@Autowired(required = false)
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	@Autowired(required = false)
	public void setMethodSecurityExpressionHandler(List<MethodSecurityExpressionHandler> handlers) {
		if (handlers.size() != 1) {
			logger.debug("Not autowiring MethodSecurityExpressionHandler since size != 1. Got " + handlers);
			return;
		}
		this.expressionHandler = handlers.get(0);
	}

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		this.context = beanFactory;
	}

	/**
	 * 获得容器中的认证管理器, 也就是在认证过滤器中的局部认证管理器
	 * @return
	 */
	private AuthenticationConfiguration getAuthenticationConfiguration() {
		return this.context.getBean(AuthenticationConfiguration.class);
	}

	/**
	 * {@link EnableGlobalMethodSecurity @EnableGlobalMethodSecurity} 是否设置prePostEnabled属性为True
	 * @return
	 */
	private boolean prePostEnabled() {
		return enableMethodSecurity().getBoolean("prePostEnabled");
	}


	/**
	 * {@link EnableGlobalMethodSecurity @EnableGlobalMethodSecurity} 是否设置securedEnabled属性为True
	 * @return
	 */
	private boolean securedEnabled() {
		return enableMethodSecurity().getBoolean("securedEnabled");
	}

	/**
	 * {@link EnableGlobalMethodSecurity @EnableGlobalMethodSecurity} 是否设置jsr250Enabled属性为True
	 * @return
	 */
	private boolean jsr250Enabled() {
		return enableMethodSecurity().getBoolean("jsr250Enabled");
	}

	private boolean isAspectJ() {
		return enableMethodSecurity().getEnum("mode") == AdviceMode.ASPECTJ;
	}

	/**
	 * 获得有关 {@link EnableGlobalMethodSecurity @EnableGlobalMethodSecurity} 的属性
	 * @return
	 */
	private AnnotationAttributes enableMethodSecurity() {
		if (this.enableMethodSecurity == null) {
			// if it is null look at this instance (i.e. a subclass was used)
			EnableGlobalMethodSecurity methodSecurityAnnotation = AnnotationUtils.findAnnotation(getClass(),
					EnableGlobalMethodSecurity.class);
			Assert.notNull(methodSecurityAnnotation, () -> EnableGlobalMethodSecurity.class.getName() + " is required");
			Map<String, Object> methodSecurityAttrs = AnnotationUtils.getAnnotationAttributes(methodSecurityAnnotation);
			this.enableMethodSecurity = AnnotationAttributes.fromMap(methodSecurityAttrs);
		}
		return this.enableMethodSecurity;
	}

}

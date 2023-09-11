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

package org.springframework.security.config.annotation.method.configuration;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;

/**
 * SpringSecurity开启权限注解(基于方法进行权限校验)
 * {@link GlobalMethodSecurityConfiguration} and override the protected methods to provide
 * custom implementations. Note that {@link EnableGlobalMethodSecurity} still must be
 * included on the class extending {@link GlobalMethodSecurityConfiguration} to determine
 * the settings.
 *
 * @author Rob Winch
 * @since 3.2
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import({ GlobalMethodSecuritySelector.class })
@EnableGlobalAuthentication
@Configuration
public @interface EnableGlobalMethodSecurity {

	/**
	 * 是否开启Pre Post注解
	 * <li>{@link org.springframework.security.access.prepost.PreAuthorize @PreAuthorize},
	 * {@link org.springframework.security.access.prepost.PostAuthorize @PostAuthorize},
	 * {@link org.springframework.security.access.prepost.PostFilter @PostFilter},
	 * {@link org.springframework.security.access.prepost.PreFilter @PreFilter}</li>
	 * @return true if pre post annotations should be enabled false otherwise.
	 */
	boolean prePostEnabled() default false;

	/**
	 * 是否开启{@link Secured @Secured}
	 */
	boolean securedEnabled() default false;

	/**
	 * 启用 JSR-250 注解
	 * <li>{@link javax.annotation.security.RolesAllowed @RolesAllowed}.
	 * {@link javax.annotation.security.PermitAll @RolesAllowed},
	 * {@link javax.annotation.security.DenyAll @RolesAllowed}</li>
	 * @return true if JSR-250 should be enabled false otherwise.
	 */
	boolean jsr250Enabled() default false;

	/**
	 * <ul>
	 *     <li>True：直接使用Cglib代理目标类</li>
	 *     <li>False：如果目标类有或者就是是一个接口，使用JDK，否则使用Cglib</li>
	 *     <li>由于这个值后面会直接设置到{@link org.springframework.aop.framework.autoproxy.InfrastructureAdvisorAutoProxyCreator InfrastructureAdvisorAutoProxyCreator}
	 *     所有这将影响到所有Spring管理的Bean，比如@Transactional</li>
	 * </ul>
	 */
	boolean proxyTargetClass() default false;

	/**
	 * Indicate how security advice should be applied. The default is
	 * {@link AdviceMode#PROXY}.
	 * @see AdviceMode
	 * @return the {@link AdviceMode} to use
	 */
	AdviceMode mode() default AdviceMode.PROXY;

	/**
	 * Indicate the ordering of the execution of the security advisor when multiple
	 * advices are applied at a specific joinpoint. The default is
	 * {@link Ordered#LOWEST_PRECEDENCE}.
	 * @return the order the security advisor should be applied
	 */
	int order() default Ordered.LOWEST_PRECEDENCE;

}

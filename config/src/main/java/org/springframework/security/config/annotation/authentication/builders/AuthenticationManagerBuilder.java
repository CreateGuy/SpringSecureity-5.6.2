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

package org.springframework.security.config.annotation.authentication.builders;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.UserDetailsAwareConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

/**
 * {@link SecurityBuilder} used to create an {@link AuthenticationManager}. Allows for
 * easily building in memory authentication, LDAP authentication, JDBC based
 * authentication, adding {@link UserDetailsService}, and adding
 * {@link AuthenticationProvider}'s.
 *
 * @author Rob Winch
 * @since 3.2
 */
public class AuthenticationManagerBuilder
		extends AbstractConfiguredSecurityBuilder<AuthenticationManager, AuthenticationManagerBuilder>
		implements ProviderManagerBuilder<AuthenticationManagerBuilder> {

	private final Log logger = LogFactory.getLog(getClass());

	/**
	 * 父认证管理器
	 * 一般情况：只有当前构建器是局部认证管理器的时候才会有父认证管理器(全局认证管理器)
	 */
	private AuthenticationManager parentAuthenticationManager;

	/**
	 * 认证提供者集合
	 * 如果当前是局部认证管理器构建器，那么就会被放入ShardObject中
	 * 那么当匿名用户配置类就会放入一个认证提供者，其他的配置类也有可能
	 */
	private List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private UserDetailsService defaultUserDetailsService;

	/**
	 * 在认证成功后是否擦除密码
	 */
	private Boolean eraseCredentials;

	/**
	 * 认证事件推送器
	 */
	private AuthenticationEventPublisher eventPublisher;

	/**
	 * Creates a new instance
	 * @param objectPostProcessor the {@link ObjectPostProcessor} instance to use.
	 */
	public AuthenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor, true);
	}

	/**
	 * Allows providing a parent {@link AuthenticationManager} that will be tried if this
	 * {@link AuthenticationManager} was unable to attempt to authenticate the provided
	 * {@link Authentication}.
	 * @param authenticationManager the {@link AuthenticationManager} that should be used
	 * if the current {@link AuthenticationManager} was unable to attempt to authenticate
	 * the provided {@link Authentication}.
	 * @return the {@link AuthenticationManagerBuilder} for further adding types of
	 * authentication
	 */
	public AuthenticationManagerBuilder parentAuthenticationManager(AuthenticationManager authenticationManager) {
		if (authenticationManager instanceof ProviderManager) {
			eraseCredentials(((ProviderManager) authenticationManager).isEraseCredentialsAfterAuthentication());
		}
		this.parentAuthenticationManager = authenticationManager;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationEventPublisher}
	 * @param eventPublisher the {@link AuthenticationEventPublisher} to use
	 * @return the {@link AuthenticationManagerBuilder} for further customizations
	 */
	public AuthenticationManagerBuilder authenticationEventPublisher(AuthenticationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "AuthenticationEventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
		return this;
	}

	/**
	 * @param eraseCredentials true if {@link AuthenticationManager} should clear the
	 * credentials from the {@link Authentication} object after authenticating
	 * @return the {@link AuthenticationManagerBuilder} for further customizations
	 */
	public AuthenticationManagerBuilder eraseCredentials(boolean eraseCredentials) {
		this.eraseCredentials = eraseCredentials;
		return this;
	}

	/**
	 * Add in memory authentication to the {@link AuthenticationManagerBuilder} and return
	 * a {@link InMemoryUserDetailsManagerConfigurer} to allow customization of the in
	 * memory authentication.
	 *
	 * <p>
	 * This method also ensure that a {@link UserDetailsService} is available for the
	 * {@link #getDefaultUserDetailsService()} method. Note that additional
	 * {@link UserDetailsService}'s may override this {@link UserDetailsService} as the
	 * default.
	 * </p>
	 * @return a {@link InMemoryUserDetailsManagerConfigurer} to allow customization of
	 * the in memory authentication
	 * @throws Exception if an error occurs when adding the in memory authentication
	 */
	public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
			throws Exception {
		return apply(new InMemoryUserDetailsManagerConfigurer<>());
	}

	/**
	 * Add JDBC authentication to the {@link AuthenticationManagerBuilder} and return a
	 * {@link JdbcUserDetailsManagerConfigurer} to allow customization of the JDBC
	 * authentication.
	 *
	 * <p>
	 * When using with a persistent data store, it is best to add users external of
	 * configuration using something like <a href="https://flywaydb.org/">Flyway</a> or
	 * <a href="https://www.liquibase.org/">Liquibase</a> to create the schema and adding
	 * users to ensure these steps are only done once and that the optimal SQL is used.
	 * </p>
	 *
	 * <p>
	 * This method also ensure that a {@link UserDetailsService} is available for the
	 * {@link #getDefaultUserDetailsService()} method. Note that additional
	 * {@link UserDetailsService}'s may override this {@link UserDetailsService} as the
	 * default. See the <a href=
	 * "https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#user-schema"
	 * >User Schema</a> section of the reference for the default schema.
	 * </p>
	 * @return a {@link JdbcUserDetailsManagerConfigurer} to allow customization of the
	 * JDBC authentication
	 * @throws Exception if an error occurs when adding the JDBC authentication
	 */
	public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication() throws Exception {
		return apply(new JdbcUserDetailsManagerConfigurer<>());
	}

	/**
	 * Add authentication based upon the custom {@link UserDetailsService} that is passed
	 * in. It then returns a {@link DaoAuthenticationConfigurer} to allow customization of
	 * the authentication.
	 *
	 * <p>
	 * This method also ensure that the {@link UserDetailsService} is available for the
	 * {@link #getDefaultUserDetailsService()} method. Note that additional
	 * {@link UserDetailsService}'s may override this {@link UserDetailsService} as the
	 * default.
	 * </p>
	 * @return a {@link DaoAuthenticationConfigurer} to allow customization of the DAO
	 * authentication
	 * @throws Exception if an error occurs when adding the {@link UserDetailsService}
	 * based authentication
	 */
	public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder, T> userDetailsService(
			T userDetailsService) throws Exception {
		this.defaultUserDetailsService = userDetailsService;
		return apply(new DaoAuthenticationConfigurer<>(userDetailsService));
	}

	/**
	 * Add LDAP authentication to the {@link AuthenticationManagerBuilder} and return a
	 * {@link LdapAuthenticationProviderConfigurer} to allow customization of the LDAP
	 * authentication.
	 *
	 * <p>
	 * This method <b>does NOT</b> ensure that a {@link UserDetailsService} is available
	 * for the {@link #getDefaultUserDetailsService()} method.
	 * @return a {@link LdapAuthenticationProviderConfigurer} to allow customization of
	 * the LDAP authentication
	 * @throws Exception if an error occurs when adding the LDAP authentication
	 */
	public LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder> ldapAuthentication() throws Exception {
		return apply(new LdapAuthenticationProviderConfigurer<>());
	}

	/**
	 * Add authentication based upon the custom {@link AuthenticationProvider} that is
	 * passed in. Since the {@link AuthenticationProvider} implementation is unknown, all
	 * customizations must be done externally and the {@link AuthenticationManagerBuilder}
	 * is returned immediately.
	 *
	 * <p>
	 * This method <b>does NOT</b> ensure that the {@link UserDetailsService} is available
	 * for the {@link #getDefaultUserDetailsService()} method.
	 *
	 * Note that an {@link Exception} might be thrown if an error occurs when adding the
	 * {@link AuthenticationProvider}.
	 * @return a {@link AuthenticationManagerBuilder} to allow further authentication to
	 * be provided to the {@link AuthenticationManagerBuilder}
	 */
	@Override
	public AuthenticationManagerBuilder authenticationProvider(AuthenticationProvider authenticationProvider) {
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	/**
	 * 创建认证管理器（全局和局部都会有构建流程）
	 * @return
	 * @throws Exception
	 */
	@Override
	protected ProviderManager performBuild() throws Exception {
		if (!isConfigured()) {
			this.logger.debug("No authenticationProviders and no parentAuthenticationManager defined. Returning null.");
			return null;
		}
		ProviderManager providerManager = new ProviderManager(this.authenticationProviders,
				this.parentAuthenticationManager);
		//是否在认证成功后是否擦除密码
		if (this.eraseCredentials != null) {
			providerManager.setEraseCredentialsAfterAuthentication(this.eraseCredentials);
		}
		//设置认证事件推送器
		if (this.eventPublisher != null) {
			providerManager.setAuthenticationEventPublisher(this.eventPublisher);
		}
		providerManager = postProcess(providerManager);
		return providerManager;
	}

	/**
	 * 有了认证提供者，并且也有全局认证管理器就返回true
	 */
	public boolean isConfigured() {
		return !this.authenticationProviders.isEmpty() || this.parentAuthenticationManager != null;
	}

	/**
	 * Gets the default {@link UserDetailsService} for the
	 * {@link AuthenticationManagerBuilder}. The result may be null in some circumstances.
	 * @return the default {@link UserDetailsService} for the
	 * {@link AuthenticationManagerBuilder}
	 */
	public UserDetailsService getDefaultUserDetailsService() {
		return this.defaultUserDetailsService;
	}

	/**
	 * Captures the {@link UserDetailsService} from any {@link UserDetailsAwareConfigurer}
	 * .
	 * @param configurer the {@link UserDetailsAwareConfigurer} to capture the
	 * {@link UserDetailsService} from.
	 * @return the {@link UserDetailsAwareConfigurer} for further customizations
	 * @throws Exception if an error occurs
	 */
	private <C extends UserDetailsAwareConfigurer<AuthenticationManagerBuilder, ? extends UserDetailsService>> C apply(
			C configurer) throws Exception {
		this.defaultUserDetailsService = configurer.getUserDetailsService();
		return super.apply(configurer);
	}

}

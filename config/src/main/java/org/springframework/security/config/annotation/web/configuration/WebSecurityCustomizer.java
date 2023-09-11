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

package org.springframework.security.config.annotation.web.configuration;

import org.springframework.security.config.annotation.web.builders.WebSecurity;

/**
 * 貌似是因为WebSecurityConfigurerAdapter 5.7之久的版本会被弃用，所有出现了新的操作WebSecurity的接口，例子如下
 * @Bean
 * public WebSecurityCustomizer ignoringCustomizer() {
 *  return (web) -> web.ignoring().antMatchers("/ignore1", "/ignore2");
 * }
 */
@FunctionalInterface
public interface WebSecurityCustomizer {

	/**
	 * Performs the customizations on {@link WebSecurity}.
	 * @param web the instance of {@link WebSecurity} to apply to customizations to
	 */
	void customize(WebSecurity web);

}

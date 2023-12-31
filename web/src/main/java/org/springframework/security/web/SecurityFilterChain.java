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

package org.springframework.security.web;

import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

/**
 * SpringSecurity的过滤器链。
 * 一般用于配置在FilterChainProxy中
 */
public interface SecurityFilterChain {

	/**
	 * 是否需要执行这个过滤器
	 * @param request
	 * @return
	 */
	boolean matches(HttpServletRequest request);

	List<Filter> getFilters();

}

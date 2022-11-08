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

package org.springframework.security.config.http;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContext;

/**
 * Spring Security的会话创建策略
 */
public enum SessionCreationPolicy {

	/**
	 * 总是 {@link HttpSession}
	 */
	ALWAYS,

	/**
	 * 永远不会创建 {@link HttpSession}, 除非他已经存在
	 * 应该是不会由Spring Security创建
	 */
	NEVER,

	/**
	 * 在需要的时候创建 {@link HttpSession}
	 */
	IF_REQUIRED,

	/**
	 * Spring Security永远不会创建 {@link HttpSession}，也永远不会使用它获取 {@link HttpSession}
	 */
	STATELESS

}

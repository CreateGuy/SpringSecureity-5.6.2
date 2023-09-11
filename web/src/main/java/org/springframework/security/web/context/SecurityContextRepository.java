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

package org.springframework.security.web.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;

/**
 * 翻译过来叫安全上下文存储库，我更愿意叫他HttpSession级别的安全上下文存储策略，毕竟也就只有这一个有用的实现类
 * 	用于在请求之间持久化SecurityContext的策略，由SecurityContextPersistenceFilter使用
 * 	拿到之后，在从线程级别的安全上下文存储策略中 存储或者删除上下文 且当请求完成后存储上下文
 * 	使用的持久性机制将取决于实现，但最常见的情况是使用HttpSession来存储上下文。
 */
public interface SecurityContextRepository {

	/**
	 * 获得当前安全上下文
	 */
	SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder);

	/**
	 * 存储安全上下文
	 * @param context the non-null context which was obtained from the holder.
	 * @param request
	 * @param response
	 */
	void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response);

	/**
	 * 查看request是否包含当前用户的安全上下文
	 * for the current request.
	 * @param request the current request
	 * @return true if a context is found for the request, false otherwise
	 */
	boolean containsContext(HttpServletRequest request);

}

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

package org.springframework.security.web.savedrequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 请求缓存器：
 */
public interface RequestCache {

	/**
	 * <ul>
	 *     <li>
	 *          在身份验证发生后，缓存当前请求以供以后使用
	 * 			比如说：在一个论坛的帖子中，进行回帖，然后因为没有登录，先将回帖的信息保存到请求缓存器中，再重定向到登录页
	 * 	 		然后登陆成功后就会获取请求缓存器中上次保存的回帖信息，然后将当前request进行包装，变成一个回帖请求
	 *     </li>
	 *     <li>
	 *         通常发生在{@link org.springframework.security.web.access.ExceptionTranslationFilter}中
	 *     </li>
	 * </ul>
	 */
	void saveRequest(HttpServletRequest request, HttpServletResponse response);

	/**
	 * 返回已保存的请求，保留其缓存状态。
	 * @param request the current request
	 * @return the saved request which was previously cached, or null if there is none.
	 */
	SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response);

	/**
	 * 如果与当前请求匹配，则返回保存的请求的包装器。保存的请求应该从缓存中删除。
	 * @param request
	 * @param response
	 * @return the wrapped save request, if it matches the original, or null if there is
	 * no cached request or it doesn't match.
	 */
	HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response);

	/**
	 * 删除缓存的请求缓存
	 * @param request the current request, allowing access to the cache.
	 */
	void removeRequest(HttpServletRequest request, HttpServletResponse response);

}

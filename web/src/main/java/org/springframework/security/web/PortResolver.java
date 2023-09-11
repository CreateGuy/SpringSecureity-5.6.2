/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import javax.servlet.ServletRequest;

/**
 *	端口解析器确定接收web请求的端口。
 *	这个接口是必需的，因为在某些情况下ServletRequest.getServerPort()可能不会返回正确的端口
 *	<li>
 *	   例如：nginx的监听端口不是默认的80端口，那么request.getServerPort()方法无法获得正确的端口号，仍然拿到到80端口
 *	</li>
 */
public interface PortResolver {

	/**
	 * Indicates the port the <code>ServletRequest</code> was received on.
	 * @param request that the method should lookup the port for
	 * @return the port the request was received on
	 */
	int getServerPort(ServletRequest request);

}

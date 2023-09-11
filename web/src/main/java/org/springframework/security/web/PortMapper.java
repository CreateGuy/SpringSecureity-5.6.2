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

/**
 * 端口映射器，将Https可以和Http的端口进行互相映射
 * <p>
 *     我猜测：如果有nginx的情况，nginx采用 Https，而后端服务采用 Http，那么request.getServerPort()就会获取Https的端口，那么就需要映射
 * </p>
 */
public interface PortMapper {

	/**
	 * 返回与指定HTTPS端口关联的HTTP端口
	 * <P>
	 * Returns <code>null</code> if unknown.
	 * </p>
	 * @param httpsPort
	 * @return the HTTP port or <code>null</code> if unknown
	 */
	Integer lookupHttpPort(Integer httpsPort);

	/**
	 * 返回与指定HTTP端口关联的HTTPS端口
	 * <P>
	 * Returns <code>null</code> if unknown.
	 * </p>
	 * @param httpPort
	 * @return the HTTPS port or <code>null</code> if unknown
	 */
	Integer lookupHttpsPort(Integer httpPort);

}

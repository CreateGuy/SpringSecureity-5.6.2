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

import org.springframework.util.Assert;

/**
 * PortResolver的具体实现，它从ServletRequest获取端口
 */
public class PortResolverImpl implements PortResolver {

	/**
	 * 端口映射器
	 */
	private PortMapper portMapper = new PortMapperImpl();

	public PortMapper getPortMapper() {
		return this.portMapper;
	}

	/**
	 * 获得真实端口
	 * @param request that the method should lookup the port for
	 * @return
	 */
	@Override
	public int getServerPort(ServletRequest request) {
		//从Request中获取
		int serverPort = request.getServerPort();
		//获得协议名称
		String scheme = request.getScheme().toLowerCase();
		//进行端口映射
		Integer mappedPort = getMappedPort(serverPort, scheme);
		return (mappedPort != null) ? mappedPort : serverPort;
	}

	/**
	 * 进行端口映射
	 * @param serverPort
	 * @param scheme
	 * @return
	 */
	private Integer getMappedPort(int serverPort, String scheme) {
		if ("http".equals(scheme)) {
			return this.portMapper.lookupHttpPort(serverPort);
		}
		if ("https".equals(scheme)) {
			return this.portMapper.lookupHttpsPort(serverPort);
		}
		return null;
	}

	public void setPortMapper(PortMapper portMapper) {
		Assert.notNull(portMapper, "portMapper cannot be null");
		this.portMapper = portMapper;
	}

}

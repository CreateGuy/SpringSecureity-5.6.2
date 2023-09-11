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

package org.springframework.security.web.access.channel;

/**
 * 通过使用HTTP重新尝试原始请求，启动一个不安全的通道
 */
public class RetryWithHttpEntryPoint extends AbstractRetryEntryPoint {

	public RetryWithHttpEntryPoint() {
		super("http://", 80);
	}

	@Override
	protected Integer getMappedPort(Integer mapFromPort) {
		return getPortMapper().lookupHttpPort(mapFromPort);
	}

}

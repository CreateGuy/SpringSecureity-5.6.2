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

package org.springframework.security.access.event;

/**
 * 每当请求公共接口的时候发布的事件
 * <ul>
 *     <li>
 *         比如说 /a 不需要认证权限，那么就会发布这个事件
 *     </li>
 * </ul>
 */
public class PublicInvocationEvent extends AbstractAuthorizationEvent {

	/**
	 * Construct the event, passing in the public secure object.
	 * @param secureObject the public secure object
	 */
	public PublicInvocationEvent(Object secureObject) {
		super(secureObject);
	}

}

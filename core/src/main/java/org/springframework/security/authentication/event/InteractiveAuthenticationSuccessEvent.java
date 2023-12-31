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

package org.springframework.security.authentication.event;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * 表示交互认证成功的事件
 * <ul>
 *     <li>
 *         会在 表单认证，记住我认证，CAS单点认证成功后调用
 *     </li>
 * </ul>
 */
public class InteractiveAuthenticationSuccessEvent extends AbstractAuthenticationEvent {

	private final Class<?> generatedBy;

	public InteractiveAuthenticationSuccessEvent(Authentication authentication, Class<?> generatedBy) {
		super(authentication);
		Assert.notNull(generatedBy, "generatedBy cannot be null");
		this.generatedBy = generatedBy;
	}

	/**
	 * Getter for the <code>Class</code> that generated this event. This can be useful for
	 * generating additional logging information.
	 * @return the class
	 */
	public Class<?> getGeneratedBy() {
		return this.generatedBy;
	}

}

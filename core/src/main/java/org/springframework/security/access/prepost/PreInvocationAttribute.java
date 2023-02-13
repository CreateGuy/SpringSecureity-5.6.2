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

package org.springframework.security.access.prepost;

import org.springframework.security.access.ConfigAttribute;

/**
 * 标记接口，表示在方法执行前需要判断的表达式
 * <li>通常来源是 {@link PreFilter @PreFilter} 和 {@link PreAuthorize @PreAuthorize}</li>
 * <li>在 {@link PreInvocationAuthorizationAdvice} 中被调用</li>
 */
public interface PreInvocationAttribute extends ConfigAttribute {

}

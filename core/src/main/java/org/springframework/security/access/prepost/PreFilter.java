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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 在方法执行前被调用：对于集合进行过滤，不符合的将会被删除
 * <ul>
 *     <li>参数必须是支持删除的集合类型，不支持过滤空数组</li>
 *     <li>对于只有一个参数且为集合类型的方法，此参数将被用作过滤器目标</li>
 * </ul>
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface PreFilter {

	/**
	 * 匹配表达式：Spring-EL表达式
	 */
	String value();

	/**
	 * 需要过滤的参数名称(必须是非空集合)
	 */
	String filterTarget() default "";

}

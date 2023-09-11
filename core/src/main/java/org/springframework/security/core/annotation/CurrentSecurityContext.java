/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.core.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 填充方法入参中的 {@link org.springframework.security.core.context.SecurityContext} 参数
 *
 * <p>
 * See: <a href=
 * "{@docRoot}/org/springframework/security/web/bind/support/CurrentSecurityContextArgumentResolver.html"
 * > CurrentSecurityContextArgumentResolver</a> For Servlet
 * </p>
 *
 * <p>
 * See: <a href=
 * "{@docRoot}/org/springframework/security/web/reactive/result/method/annotation/CurrentSecurityContextArgumentResolver.html"
 * > CurrentSecurityContextArgumentResolver</a> For WebFlux
 * </p>
 */
@Target({ ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CurrentSecurityContext {

	/**
	 * 如果注解放在参数上，但是参数类型不对，不是 {@link org.springframework.security.core.context.SecurityContext}，是否抛出异常，默认不抛出
	 */
	boolean errorOnInvalidType() default false;

	/**
	 * 以指定的 SpEL 来解析参数，eg： @CurrentSecurityContext(expression="authentication") Authentication authentication
	 */
	String expression() default "";

}

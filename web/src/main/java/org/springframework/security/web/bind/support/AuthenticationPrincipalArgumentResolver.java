/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.web.bind.support;

import java.lang.annotation.Annotation;

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.bind.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * 专门解析 @{@link AuthenticationPrincipal}.例如
 * <pre>
 * &#64;Controller
 * public class MyController {
 *     &#64;RequestMapping("/user/current/show")
 *     public String show(@AuthenticationPrincipal CustomUser customUser) {
 *         // do something with CustomUser
 *         return "view";
 *     }
 * }
 * </pre>
 *
 * <p>
 * Will resolve the CustomUser argument using {@link Authentication#getPrincipal()} from
 * the {@link SecurityContextHolder}. If the {@link Authentication} or
 * {@link Authentication#getPrincipal()} is null, it will return null. If the types do not
 * match, null will be returned unless
 * {@link AuthenticationPrincipal#errorOnInvalidType()} is true in which case a
 * {@link ClassCastException} will be thrown.
 *
 * <p>
 * Alternatively, users can create a custom meta annotation as shown below:
 *
 * <pre>
 * &#064;Target({ ElementType.PARAMETER })
 * &#064;Retention(RetentionPolicy.RUNTIME)
 * &#064;AuthenticationPrincipal
 * public @interface CurrentUser {
 * }
 * </pre>
 *
 * <p>
 * The custom annotation can then be used instead. For example:
 *
 * <pre>
 * &#64;Controller
 * public class MyController {
 *     &#64;RequestMapping("/user/current/show")
 *     public String show(@CurrentUser CustomUser customUser) {
 *         // do something with CustomUser
 *         return "view";
 *     }
 * }
 * </pre>
 *
 * @author Rob Winch
 * @since 3.2
 * @deprecated Use
 * {@link org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver}
 * instead.
 */
@Deprecated
public final class AuthenticationPrincipalArgumentResolver implements HandlerMethodArgumentResolver {

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return findMethodAnnotation(AuthenticationPrincipal.class, parameter) != null;
	}

	@Override
	public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
			NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
		// 通过线程级别的安全上下文获得认证对象
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			return null;
		}
		// 获得用户对象
		Object principal = authentication.getPrincipal();
		// 如果两者类型不匹配是否抛出异常
		if (principal != null && !parameter.getParameterType().isAssignableFrom(principal.getClass())) {
			AuthenticationPrincipal authPrincipal = findMethodAnnotation(AuthenticationPrincipal.class, parameter);
			if (authPrincipal.errorOnInvalidType()) {
				throw new ClassCastException(principal + " is not assignable to " + parameter.getParameterType());
			}
			return null;
		}
		return principal;
	}

	/**
	 * 获得指定注解
	 */
	private <T extends Annotation> T findMethodAnnotation(Class<T> annotationClass, MethodParameter parameter) {
		T annotation = parameter.getParameterAnnotation(annotationClass);
		if (annotation != null) {
			return annotation;
		}
		Annotation[] annotationsToSearch = parameter.getParameterAnnotations();
		for (Annotation toSearch : annotationsToSearch) {
			annotation = AnnotationUtils.findAnnotation(toSearch.annotationType(), annotationClass);
			if (annotation != null) {
				return annotation;
			}
		}
		return null;
	}

}

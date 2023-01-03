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

package org.springframework.security.web.method.annotation;

import java.lang.annotation.Annotation;

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.BeanResolver;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * 解析标注了 {@link CurrentSecurityContext} 注解的参数
 * <ol>
 *     <li> 支持 {@link Controller} 方法中的入参中有标注了 {@link CurrentSecurityContext} 注解放在 {@link SecurityContext} 参数上 </li>
 *     <li> 支持 Spring SpEl表达式从 SecurityContext中获取值 eg：@CurrentSecurityContext(expression="authentication") Authentication authentication</li>
 * </ol>
 */
public final class CurrentSecurityContextArgumentResolver implements HandlerMethodArgumentResolver {

	private ExpressionParser parser = new SpelExpressionParser();

	private BeanResolver beanResolver;

	/**
	 * 此参数解析器只能支持带有 {@code CurrentSecurityContext} 注解的参数
	 * @param parameter
	 * @return
	 */
	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return findMethodAnnotation(CurrentSecurityContext.class, parameter) != null;
	}

	@Override
	public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
			NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
		// 从线程级别的策略中拿到安全上下文
		SecurityContext securityContext = SecurityContextHolder.getContext();
		if (securityContext == null) {
			return null;
		}
		Object securityContextResult = securityContext;
		// 从参数上拿到指定的 CurrentSecurityContext 注解信息
		CurrentSecurityContext annotation = findMethodAnnotation(CurrentSecurityContext.class, parameter);
		String expressionToParse = annotation.expression();
		// 是否以 SpEL 进行解析
		// SpEL 不懂
		if (StringUtils.hasLength(expressionToParse)) {
			StandardEvaluationContext context = new StandardEvaluationContext();
			context.setRootObject(securityContext);
			context.setVariable("this", securityContext);
			context.setBeanResolver(this.beanResolver);
			Expression expression = this.parser.parseExpression(expressionToParse);
			securityContextResult = expression.getValue(context);
		}
		// 如果有安全上下文，但是参数类型不对
		if (securityContextResult != null
				&& !parameter.getParameterType().isAssignableFrom(securityContextResult.getClass())) {
			// 是否抛出异常，还是返回空
			if (annotation.errorOnInvalidType()) {
				throw new ClassCastException(
						securityContextResult + " is not assignable to " + parameter.getParameterType());
			}
			return null;
		}
		return securityContextResult;
	}

	/**
	 * Set the {@link BeanResolver} to be used on the expressions
	 * @param beanResolver the {@link BeanResolver} to use
	 */
	public void setBeanResolver(BeanResolver beanResolver) {
		Assert.notNull(beanResolver, "beanResolver cannot be null");
		this.beanResolver = beanResolver;
	}

	/**
	 * 在指定的方法参数上，获得指定的注解
	 * @param annotationClass the class of the {@link Annotation} to find on the
	 * {@link MethodParameter}
	 * @param parameter the {@link MethodParameter} to search for an {@link Annotation}
	 * @return the {@link Annotation} that was found or null.
	 */
	private <T extends Annotation> T findMethodAnnotation(Class<T> annotationClass, MethodParameter parameter) {
		// 拿到参数上的指定注解
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

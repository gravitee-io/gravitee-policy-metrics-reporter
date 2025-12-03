/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.metricsreporter.freemarker;

import freemarker.ext.beans.ClassMemberAccessPolicy;
import freemarker.ext.beans.MemberAccessPolicy;
import freemarker.template.utility.ClassUtil;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public final class LegacyDefaultMemberAccessPolicy implements MemberAccessPolicy {

    public static final LegacyDefaultMemberAccessPolicy INSTANCE = new LegacyDefaultMemberAccessPolicy();

    private static final String UNSAFE_METHODS_PROPERTIES = "/extendedUnsafeMethods.properties";
    private static final Set<Method> UNSAFE_METHODS = createUnsafeMethodsSet();

    private static Set<Method> createUnsafeMethodsSet() {
        try {
            Properties props = ClassUtil.loadProperties(LegacyDefaultMemberAccessPolicy.class, UNSAFE_METHODS_PROPERTIES);
            Set<Method> set = new HashSet<>((props.size() * 4) / 3, 1f);
            for (Object key : props.keySet()) {
                try {
                    set.add(parseMethodSpec((String) key));
                } catch (ClassNotFoundException | NoSuchMethodException e) {}
            }
            return set;
        } catch (Exception e) {
            throw new RuntimeException("Could not load unsafe method set", e);
        }
    }

    private static Method parseMethodSpec(String methodSpec) throws ClassNotFoundException, NoSuchMethodException {
        int brace = methodSpec.indexOf('(');
        int dot = methodSpec.lastIndexOf('.', brace);
        Class<?> clazz = ClassUtil.forName(methodSpec.substring(0, dot));
        String methodName = methodSpec.substring(dot + 1, brace);
        String argSpec = methodSpec.substring(brace + 1, methodSpec.length() - 1);
        StringTokenizer tok = new StringTokenizer(argSpec, ",");
        int argcount = tok.countTokens();
        Class<?>[] argTypes = new Class[argcount];
        for (int i = 0; i < argcount; i++) {
            String argClassName = tok.nextToken();
            argTypes[i] = ClassUtil.resolveIfPrimitiveTypeName(argClassName);
            if (argTypes[i] == null) {
                argTypes[i] = ClassUtil.forName(argClassName);
            }
        }
        return clazz.getMethod(methodName, argTypes);
    }

    private LegacyDefaultMemberAccessPolicy() {}

    @Override
    public ClassMemberAccessPolicy forClass(Class<?> containingClass) {
        return CLASS_MEMBER_ACCESS_POLICY_INSTANCE;
    }

    @Override
    public boolean isToStringAlwaysExposed() {
        return true;
    }

    private static final BlacklistClassMemberAccessPolicy CLASS_MEMBER_ACCESS_POLICY_INSTANCE = new BlacklistClassMemberAccessPolicy();

    private static class BlacklistClassMemberAccessPolicy implements ClassMemberAccessPolicy {

        @Override
        public boolean isMethodExposed(Method method) {
            return !UNSAFE_METHODS.contains(method);
        }

        @Override
        public boolean isConstructorExposed(Constructor<?> constructor) {
            return true;
        }

        @Override
        public boolean isFieldExposed(Field field) {
            return true;
        }
    }
}

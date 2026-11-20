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
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * Member access policy used by the FreeMarker object wrapper of the policy.
 *
 * <p>It combines two deny-lists:</p>
 * <ul>
 *     <li><b>Unsafe methods</b> ({@value #UNSAFE_METHODS_PROPERTIES}): individual methods that are never exposed to templates
 *     (e.g. {@link Object#getClass()}).</li>
 *     <li><b>Unsafe classes</b> ({@value #UNSAFE_CLASSES_PROPERTIES}): types (and every subtype / implementation) or packages for
 *     which <i>no member at all</i> is exposed (e.g. {@link Class}, {@link ClassLoader}, {@code java.lang.reflect}, {@code sun.misc.Unsafe},
 *     {@link ProcessBuilder}...).</li>
 * </ul>
 *
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public final class LegacyDefaultMemberAccessPolicy implements MemberAccessPolicy {

    public static final LegacyDefaultMemberAccessPolicy INSTANCE = new LegacyDefaultMemberAccessPolicy();

    static final String UNSAFE_METHODS_PROPERTIES = "/extendedUnsafeMethods.properties";
    static final String UNSAFE_CLASSES_PROPERTIES = "/extendedUnsafeClasses.properties";

    private static final Set<Method> UNSAFE_METHODS = createUnsafeMethodsSet();
    private static final Set<String> UNSAFE_CLASS_NAMES;
    private static final List<String> UNSAFE_PACKAGE_PREFIXES;

    static {
        Set<String> classNames = new HashSet<>();
        Set<String> packagePrefixes = new HashSet<>();
        try {
            Properties props = ClassUtil.loadProperties(LegacyDefaultMemberAccessPolicy.class, UNSAFE_CLASSES_PROPERTIES);
            for (Object key : props.keySet()) {
                String entry = ((String) key).trim();
                if (entry.endsWith(".*")) {
                    packagePrefixes.add(entry.substring(0, entry.length() - 1));
                } else if (!entry.isEmpty()) {
                    classNames.add(entry);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Could not load unsafe class set", e);
        }
        UNSAFE_CLASS_NAMES = Collections.unmodifiableSet(classNames);
        UNSAFE_PACKAGE_PREFIXES = List.copyOf(packagePrefixes);
    }

    private static Set<Method> createUnsafeMethodsSet() {
        try {
            Properties props = ClassUtil.loadProperties(LegacyDefaultMemberAccessPolicy.class, UNSAFE_METHODS_PROPERTIES);
            Set<Method> set = new HashSet<>((props.size() * 4) / 3, 1f);
            for (Object key : props.keySet()) {
                try {
                    set.add(parseMethodSpec((String) key));
                } catch (ClassNotFoundException | NoSuchMethodException e) {
                    // Method removed from the running JDK: nothing to deny. Typos are caught by LegacyDefaultMemberAccessPolicyTest.
                }
            }
            return set;
        } catch (Exception e) {
            throw new RuntimeException("Could not load unsafe method set", e);
        }
    }

    static Method parseMethodSpec(String methodSpec) throws ClassNotFoundException, NoSuchMethodException {
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
        return isUnsafeClass(containingClass) ? DENY_ALL_CLASS_MEMBER_ACCESS_POLICY : BLACKLIST_CLASS_MEMBER_ACCESS_POLICY;
    }

    @Override
    public boolean isToStringAlwaysExposed() {
        return true;
    }

    /**
     * A class is considered unsafe if itself, or any of its superclasses or implemented interfaces, is listed in the unsafe classes
     * or belongs to an unsafe package. Names are compared (instead of {@link Class} instances) so that the check works whatever the
     * classloader the type comes from, and without having to load optional types (Spring, Vert.x, ...).
     */
    static boolean isUnsafeClass(Class<?> clazz) {
        if (clazz == null) {
            return false;
        }
        if (clazz.isArray()) {
            return isUnsafeClass(clazz.getComponentType());
        }
        Set<Class<?>> visited = new HashSet<>();
        Deque<Class<?>> toVisit = new ArrayDeque<>();
        toVisit.push(clazz);
        while (!toVisit.isEmpty()) {
            Class<?> current = toVisit.pop();
            if (!visited.add(current)) {
                continue;
            }
            if (isUnsafeName(current.getName())) {
                return true;
            }
            if (current.getSuperclass() != null) {
                toVisit.push(current.getSuperclass());
            }
            for (Class<?> itf : current.getInterfaces()) {
                toVisit.push(itf);
            }
        }
        return false;
    }

    private static boolean isUnsafeName(String className) {
        if (UNSAFE_CLASS_NAMES.contains(className)) {
            return true;
        }
        for (String prefix : UNSAFE_PACKAGE_PREFIXES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    static boolean isUnsafeMethod(Method method) {
        return UNSAFE_METHODS.contains(method) || isUnsafeClass(method.getDeclaringClass()) || isUnsafeClass(method.getReturnType());
    }

    private static final ClassMemberAccessPolicy BLACKLIST_CLASS_MEMBER_ACCESS_POLICY = new BlacklistClassMemberAccessPolicy();
    private static final ClassMemberAccessPolicy DENY_ALL_CLASS_MEMBER_ACCESS_POLICY = new DenyAllClassMemberAccessPolicy();

    private static class BlacklistClassMemberAccessPolicy implements ClassMemberAccessPolicy {

        @Override
        public boolean isMethodExposed(Method method) {
            return !isUnsafeMethod(method);
        }

        @Override
        public boolean isConstructorExposed(Constructor<?> constructor) {
            return true;
        }

        @Override
        public boolean isFieldExposed(Field field) {
            return !isUnsafeClass(field.getType());
        }
    }

    private static class DenyAllClassMemberAccessPolicy implements ClassMemberAccessPolicy {

        @Override
        public boolean isMethodExposed(Method method) {
            return false;
        }

        @Override
        public boolean isConstructorExposed(Constructor<?> constructor) {
            return false;
        }

        @Override
        public boolean isFieldExposed(Field field) {
            return false;
        }
    }
}

/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.metricsreporter.freemarker;

import static org.assertj.core.api.Assertions.assertThat;

import freemarker.ext.beans.ClassMemberAccessPolicy;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * @author GraviteeSource Team
 */
class LegacyDefaultMemberAccessPolicyTest {

    private final LegacyDefaultMemberAccessPolicy policy = LegacyDefaultMemberAccessPolicy.INSTANCE;

    @ParameterizedTest
    @ValueSource(
        strings = {
            "java.lang.Class",
            "java.lang.ClassLoader",
            "java.lang.Module",
            "java.lang.ModuleLayer",
            "java.lang.Runtime",
            "java.lang.System",
            "java.lang.Process",
            "java.lang.ProcessBuilder",
            "java.lang.ProcessHandle",
            "java.lang.Thread",
            "java.lang.reflect.Field",
            "java.lang.reflect.Method",
            "java.lang.reflect.Constructor",
            "java.lang.invoke.MethodHandles",
            "java.lang.invoke.MethodHandles$Lookup",
            "sun.misc.Unsafe",
            "java.io.File",
            "java.nio.file.Files",
            "java.net.URL",
            "java.net.URLClassLoader",
            "javax.script.ScriptEngineManager",
            "freemarker.template.utility.Execute",
            "freemarker.template.Configuration",
        }
    )
    void should_deny_every_member_of_unsafe_classes(String className) throws Exception {
        Class<?> clazz = Class.forName(className);
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeClass(clazz)).isTrue();

        ClassMemberAccessPolicy classPolicy = policy.forClass(clazz);
        for (Method method : clazz.getMethods()) {
            assertThat(classPolicy.isMethodExposed(method)).as(method.toString()).isFalse();
        }
        for (Field field : clazz.getFields()) {
            assertThat(classPolicy.isFieldExposed(field)).as(field.toString()).isFalse();
        }
        for (var constructor : clazz.getConstructors()) {
            assertThat(classPolicy.isConstructorExposed(constructor)).as(constructor.toString()).isFalse();
        }
    }

    @Test
    void should_deny_subclasses_and_implementations_of_unsafe_classes() {
        class MyLoader extends ClassLoader {}
        abstract class MyStream extends InputStream {}
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeClass(MyLoader.class)).isTrue();
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeClass(MyStream.class)).isTrue();
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeClass(Path.of("/").getClass())).isTrue();
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeClass(Class[].class)).isTrue();
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeClass(File[][].class)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(
        classes = {
            String.class, Integer.class, HashMap.class, ArrayList.class, List.class, java.util.concurrent.TimeUnit.class, Object.class,
        }
    )
    void should_allow_regular_classes(Class<?> clazz) {
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeClass(clazz)).isFalse();
    }

    @Test
    void should_hide_get_class_on_any_object() throws Exception {
        Method getClass = Object.class.getMethod("getClass");
        assertThat(policy.forClass(String.class).isMethodExposed(getClass)).isFalse();
        assertThat(policy.forClass(HashMap.class).isMethodExposed(getClass)).isFalse();
    }

    @Test
    void should_hide_methods_returning_unsafe_types() throws Exception {
        assertThat(policy.forClass(Enum.class).isMethodExposed(Enum.class.getMethod("getDeclaringClass"))).isFalse();
        assertThat(policy.forClass(Path.class).isMethodExposed(Path.class.getMethod("toFile"))).isFalse();
        assertThat(policy.forClass(java.net.URI.class).isMethodExposed(java.net.URI.class.getMethod("toURL"))).isFalse();
    }

    @Test
    void should_expose_regular_methods() throws Exception {
        ClassMemberAccessPolicy stringPolicy = policy.forClass(String.class);
        assertThat(stringPolicy.isMethodExposed(String.class.getMethod("toUpperCase"))).isTrue();
        assertThat(stringPolicy.isMethodExposed(String.class.getMethod("substring", int.class))).isTrue();
        assertThat(policy.forClass(HashMap.class).isMethodExposed(HashMap.class.getMethod("get", Object.class))).isTrue();
        assertThat(policy.forClass(Enum.class).isMethodExposed(Enum.class.getMethod("name"))).isTrue();
    }

    @Test
    void should_load_all_method_entries_of_the_payload_chain() throws Exception {
        ClassMemberAccessPolicy objectPolicy = policy.forClass(Object.class);
        // Even if the class-level deny-list were removed, the exact methods used by the reported exploit stay blacklisted
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeMethod(Class.class.getMethod("forName", Module.class, String.class))).isTrue();
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeMethod(Class.class.getMethod("getModule"))).isTrue();
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeMethod(Field.class.getMethod("trySetAccessible"))).isTrue();
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeMethod(Field.class.getMethod("get", Object.class))).isTrue();
        assertThat(LegacyDefaultMemberAccessPolicy.isUnsafeMethod(ProcessBuilder.class.getMethod("start"))).isTrue();
        assertThat(objectPolicy.isMethodExposed(Object.class.getMethod("hashCode"))).isTrue();
    }
}

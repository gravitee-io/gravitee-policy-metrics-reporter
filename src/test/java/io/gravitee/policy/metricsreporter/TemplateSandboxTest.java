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
package io.gravitee.policy.metricsreporter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import freemarker.template.Template;
import freemarker.template.TemplateException;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.policy.metricsreporter.configuration.MetricsReporterPolicyConfiguration;
import io.gravitee.policy.metricsreporter.freemarker.LegacyDefaultMemberAccessPolicy;
import io.gravitee.policy.metricsreporter.metrics.AttributesBasedExecutionContext;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Ensures that FreeMarker templates configured in the policy cannot escape the sandbox (SSTI → RCE).
 *
 * @author GraviteeSource Team
 */
class TemplateSandboxTest {

    @TempDir
    Path tempDir;

    private static class TemplateRenderer extends MetricsReporterPolicy {

        TemplateRenderer() {
            super(new MetricsReporterPolicyConfiguration());
        }

        String render(String body, Map<String, Object> model) throws IOException, TemplateException {
            Template template = getTemplate(body);
            StringWriter writer = new StringWriter();
            template.process(model, writer);
            return writer.toString();
        }
    }

    private final TemplateRenderer renderer = new TemplateRenderer();

    private Map<String, Object> model() {
        ExecutionContext ctx = mock(ExecutionContext.class);
        when(ctx.getAttribute("my-attribute")).thenReturn("my-value");
        // Gateway attributes may contain arbitrary objects: dangerous types must never be usable from templates
        when(ctx.getAttribute("pb")).thenReturn(new ProcessBuilder("id"));
        when(ctx.getAttribute("runtime")).thenReturn(Runtime.getRuntime());
        when(ctx.getAttribute("file")).thenReturn(new File("/etc/passwd"));
        when(ctx.getAttribute("path")).thenReturn(Path.of("/etc/passwd"));
        when(ctx.getAttribute("clazz")).thenReturn(String.class);
        Map<String, Object> model = new HashMap<>();
        model.put("context", new AttributesBasedExecutionContext(ctx));
        model.put("items", List.of("a", "b", "c"));
        model.put("headers", Map.of("X-Foo", List.of("bar")));
        model.put("thread", Thread.currentThread());
        model.put("loader", getClass().getClassLoader());
        model.put("anEnum", java.util.concurrent.TimeUnit.SECONDS);
        model.put("customLoader", new CustomClassLoader());
        model.put("bean", new LeakyBean());
        return model;
    }

    /** Overrides a blacklisted method: an exact-method blacklist alone would not catch it. */
    public static class CustomClassLoader extends ClassLoader {

        @Override
        public Class<?> loadClass(String name) throws ClassNotFoundException {
            return super.loadClass(name);
        }
    }

    public static class LeakyBean {

        public Class<?> type = ProcessBuilder.class;

        public String getName() {
            return "leaky";
        }

        public Object getSomething() {
            return ProcessBuilder.class;
        }

        public Class<?> getType() {
            return ProcessBuilder.class;
        }

        public ClassLoader getLoader() {
            return LeakyBean.class.getClassLoader();
        }
    }

    /**
     * Payload taken from the incident report: sun.misc.Unsafe.allocateInstance(ProcessBuilder) → pb.start().
     * The command only creates a marker file so we can assert it was never executed.
     */
    @Test
    void should_block_unsafe_process_builder_rce_from_incident_report() throws IOException {
        Path marker = tempDir.resolve("pwned");
        String payload = String.format(
            "<#assign C = context.getClass()>\n" +
            "<#assign MOD = C.getClass().getModule()>\n" +
            "<#assign LAYER = MOD.getLayer()>\n" +
            "<#list LAYER.modules() as m>\n" +
            "  <#if m.getName() == \"jdk.unsupported\">\n" +
            "    <#assign UC = C.forName(m, \"sun.misc.Unsafe\")>\n" +
            "  </#if>\n" +
            "</#list>\n" +
            "<#assign UF = UC.getDeclaredField(\"theUnsafe\")>\n" +
            "<#assign a = UF.trySetAccessible()>\n" +
            "<#assign U = UF.get(null)>\n" +
            "<#assign PB = C.forName(MOD, \"java.lang.ProcessBuilder\")>\n" +
            "<#assign pb = U.allocateInstance(PB)>\n" +
            "<#assign ign = pb.command(\"/bin/sh\",\"-c\",\"echo PWNED > %s; echo PWNED\")>\n" +
            "<#assign p = pb.start()>\n" +
            "<#assign ignored = p.waitFor()>\n" +
            "<#assign bytes = p.getInputStream().readAllBytes()>\n" +
            "<#list bytes as b>${b?c},</#list>\n",
            marker.toAbsolutePath()
        );

        assertThatThrownBy(() -> renderer.render(payload, model())).isInstanceOf(TemplateException.class);
        assertThat(Files.exists(marker)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(
        strings = {
            // Entry point: obtaining a java.lang.Class from any model object
            "${context.getClass()}",
            "${context.class}",
            "${items.getClass()}",
            "${anEnum.getDeclaringClass()}",
            // Anything on java.lang.Class (reflection, modules, class loading)
            "${anEnum.getDeclaringClass().getModule()}",
            "${anEnum.getDeclaringClass().forName('java.lang.Runtime')}",
            "${anEnum.getDeclaringClass().getDeclaredFields()?size}",
            "${anEnum.getDeclaringClass().getMethods()?size}",
            "${anEnum.getDeclaringClass().getClassLoader()}",
            "${anEnum.getDeclaringClass().getResource('/')}",
            // Class loaders
            "${loader.loadClass('java.lang.Runtime')}",
            "${loader.getParent()}",
            // Threads
            "${thread.getContextClassLoader()}",
            "${thread.getClass()}",
            "${thread.getStackTrace()?size}",
            // Overridden version of a blacklisted method
            "${customLoader.loadClass('java.lang.Runtime')}",
            // Dangerous objects reachable through the model / attributes
            "${context.attributes['pb'].start()}",
            "${context.attributes['pb'].command('id')}",
            "${context.attributes['runtime'].exec('id')}",
            "${context.attributes['runtime'].availableProcessors()}",
            "${context.attributes['file'].delete()?c}",
            "${context.attributes['file'].getName()}",
            "${context.attributes['path'].toFile()}",
            "${context.attributes['clazz'].getName()}",
            "${context.attributes['clazz'].forName('java.lang.Runtime')}",
            // Leaks through getters / fields typed with (or returning at runtime) a dangerous type
            "${bean.type.getName()}",
            "${bean.getType().getName()}",
            "${bean.something.getName()}",
            "${bean.getLoader().loadClass('java.lang.Runtime')}",
        }
    )
    void should_block_reflection_gadgets(String template) {
        assertThatThrownBy(() -> renderer.render(template, model())).isInstanceOf(TemplateException.class);
    }

    @Test
    void should_block_api_and_new_builtins() {
        assertThatThrownBy(() -> renderer.render("${context?api.getClass()}", model())).isInstanceOf(TemplateException.class);
        assertThatThrownBy(() -> renderer.render("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", model()))
            .isInstanceOf(TemplateException.class);
        assertThatThrownBy(() ->
                renderer.render(
                    "<#assign ob='freemarker.template.utility.ObjectConstructor'?new()>${ob('java.lang.ProcessBuilder','id')}",
                    model()
                )
            )
            .isInstanceOf(TemplateException.class);
    }

    @Test
    void should_still_render_legitimate_templates() throws Exception {
        String template =
            "attr=${context.attributes['my-attribute']}\n" +
            "missing=${context.attributes['unknown']!'none'}\n" +
            "<#list items as i>${i?upper_case}</#list>\n" +
            "header=${headers['X-Foo'][0]}\n" +
            "size=${items?size}\n" +
            "enum=${anEnum.name()}\n" +
            "str=${\"hello\"?cap_first}\n" +
            "bean=${bean.name}\n";

        String result = renderer.render(template, model());

        assertThat(result)
            .contains("attr=my-value")
            .contains("missing=none")
            .contains("ABC")
            .contains("header=bar")
            .contains("size=3")
            .contains("enum=SECONDS")
            .contains("str=Hello")
            .contains("bean=leaky");
    }
}

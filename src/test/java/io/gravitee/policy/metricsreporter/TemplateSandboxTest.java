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
package io.gravitee.policy.metricsreporter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import freemarker.core.ParseException;
import freemarker.core.TemplateClassResolver;
import freemarker.ext.beans.BeansWrapper;
import freemarker.template.Configuration;
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

        static Configuration configuration() {
            return templateConfiguration;
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
        String payload = """
            <#assign C = context.getClass()>
            <#assign MOD = C.getClass().getModule()>
            <#assign LAYER = MOD.getLayer()>
            <#list LAYER.modules() as m>
              <#if m.getName() == "jdk.unsupported">
                <#assign UC = C.forName(m, "sun.misc.Unsafe")>
              </#if>
            </#list>
            <#assign UF = UC.getDeclaredField("theUnsafe")>
            <#assign a = UF.trySetAccessible()>
            <#assign U = UF.get(null)>
            <#assign PB = C.forName(MOD, "java.lang.ProcessBuilder")>
            <#assign pb = U.allocateInstance(PB)>
            <#assign ign = pb.command("/bin/sh","-c","echo PWNED > %s; echo PWNED")>
            <#assign p = pb.start()>
            <#assign ignored = p.waitFor()>
            <#assign bytes = p.getInputStream().readAllBytes()>
            <#list bytes as b>${b?c},</#list>
            """.formatted(marker.toAbsolutePath());

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
        assertThatThrownBy(() ->
            renderer.render("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", model())
        ).isInstanceOf(TemplateException.class);
        assertThatThrownBy(() ->
            renderer.render(
                "<#assign ob='freemarker.template.utility.ObjectConstructor'?new()>${ob('java.lang.ProcessBuilder','id')}",
                model()
            )
        ).isInstanceOf(TemplateException.class);
    }

    /**
     * The whole defense against <code>?new</code> / <code>?api</code> based payloads (e.g. CVE-2025-70830) relies on these settings.
     */
    @Test
    void should_configure_freemarker_restrictively() {
        Configuration configuration = TemplateRenderer.configuration();
        assertThat(configuration.getNewBuiltinClassResolver()).isSameAs(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
        assertThat(configuration.isAPIBuiltinEnabled()).isFalse();
        assertThat(configuration.getObjectWrapper()).isInstanceOf(BeansWrapper.class);
        assertThat(((BeansWrapper) configuration.getObjectWrapper()).getMemberAccessPolicy()).isSameAs(
            LegacyDefaultMemberAccessPolicy.INSTANCE
        );
    }

    /**
     * CVE-2025-70830 (Datart): FreeMarker SSTI → RCE through <code>ObjectConstructor?new()</code> + {@link ProcessBuilder}.
     */
    @Test
    void should_block_cve_2025_70830_object_constructor_process_builder() {
        Path marker = tempDir.resolve("pwned");
        String payload = """
            <#assign ob="freemarker.template.utility.ObjectConstructor"?new()>
            <#assign pb=ob("java.lang.ProcessBuilder",["/bin/sh","-c","touch %s"])>
            ${pb.start()}
            """.formatted(marker.toAbsolutePath());

        assertThatThrownBy(() -> renderer.render(payload, model()))
            .isInstanceOf(TemplateException.class)
            .hasMessageContaining("ObjectConstructor")
            .hasMessageContaining("not allowed");
        assertThat(Files.exists(marker)).isFalse();
    }

    /**
     * CVE-2025-70830 (Datart), advanced variant: <code>ObjectConstructor?new()</code> + {@link javax.script.ScriptEngineManager}.
     */
    @Test
    void should_block_cve_2025_70830_object_constructor_script_engine() {
        String payload = """
            <#assign ob='freemarker.template.utility.ObjectConstructor'?new()>
            <#assign sem=ob('javax.script.ScriptEngineManager')>
            <#assign engine=sem.getEngineByName('js')>
            ${engine.eval('1+1')}
            """;

        assertThatThrownBy(() -> renderer.render(payload, model()))
            .isInstanceOf(TemplateException.class)
            .hasMessageContaining("ObjectConstructor")
            .hasMessageContaining("not allowed");
    }

    /**
     * Templates must not be able to re-enable what the configuration disables (<code>?new</code>, <code>?api</code>, object wrapper).
     */
    @ParameterizedTest
    @ValueSource(
        strings = {
            "<#setting new_builtin_class_resolver='unrestricted'><#assign ob='freemarker.template.utility.ObjectConstructor'?new()>${ob('java.lang.ProcessBuilder','touch','%s').start()}",
            "<#setting newBuiltinClassResolver='unrestricted'><#assign ex='freemarker.template.utility.Execute'?new()>${ex('touch %s')}",
            "<#setting new_builtin_class_resolver='allows_nothing, freemarker.template.utility.Execute'><#assign ex='freemarker.template.utility.Execute'?new()>${ex('touch %s')}",
            "<#setting api_builtin_enabled=true>${context?api.getClass().forName('java.lang.ProcessBuilder')} %s",
            "<#setting object_wrapper='DefaultObjectWrapper(2.3.30)'>${context.getClass().forName('java.lang.ProcessBuilder')} %s",
            "<#setting template_loader='freemarker.cache.FileTemplateLoader'>%s",
            // Same payloads, evaluated dynamically
            "<#assign t=r\"<#assign ex='freemarker.template.utility.Execute'?new()>${ex('touch %s')}\"?interpret><@t/>",
            "${\"'freemarker.template.utility.Execute'?new()('touch %s')\"?eval}",
        }
    )
    void should_not_allow_templates_to_relax_the_sandbox(String template) {
        Path marker = tempDir.resolve("pwned");
        String payload = template.formatted(marker.toAbsolutePath());

        assertThatThrownBy(() -> renderer.render(payload, model())).isInstanceOfAny(TemplateException.class, ParseException.class);
        assertThat(Files.exists(marker)).isFalse();
    }

    @Test
    void should_still_render_legitimate_templates() throws Exception {
        String template = """
            attr=${context.attributes['my-attribute']}
            missing=${context.attributes['unknown']!'none'}
            <#list items as i>${i?upper_case}</#list>
            header=${headers['X-Foo'][0]}
            size=${items?size}
            enum=${anEnum.name()}
            str=${"hello"?cap_first}
            bean=${bean.name}
            """;

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

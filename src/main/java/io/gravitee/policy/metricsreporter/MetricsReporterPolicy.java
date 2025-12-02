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

import freemarker.core.TemplateClassResolver;
import freemarker.template.Configuration;
import freemarker.template.DefaultObjectWrapperBuilder;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.stream.BufferedReadWriteStream;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.node.vertx.proxy.VertxProxyOptionsUtils;
import io.gravitee.policy.api.annotations.OnResponseContent;
import io.gravitee.policy.metricsreporter.configuration.MetricsReporterPolicyConfiguration;
import io.gravitee.policy.metricsreporter.freemarker.CustomTemplateLoader;
import io.gravitee.policy.metricsreporter.freemarker.LegacyDefaultMemberAccessPolicy;
import io.gravitee.policy.metricsreporter.metrics.AttributesBasedExecutionContext;
import io.gravitee.policy.metricsreporter.metrics.RequestMetrics;
import io.gravitee.policy.metricsreporter.metrics.ResponseMetrics;
import io.gravitee.policy.metricsreporter.utils.Sha1;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.*;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class MetricsReporterPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(MetricsReporterPolicy.class);

    private static final String HTTPS_SCHEME = "https";

    private final MetricsReporterPolicyConfiguration configuration;

    private HttpClient client;
    private static final CustomTemplateLoader templateLoader = new CustomTemplateLoader();
    private static final Configuration templateConfiguration = loadConfiguration();

    public MetricsReporterPolicy(final MetricsReporterPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnResponseContent
    public ReadWriteStream<Buffer> onResponseContent(ExecutionContext context) {
        return new BufferedReadWriteStream() {
            @Override
            public void end() {
                // Ensure everything has been pushed back to the client
                super.end();

                // We must push the report metrics execution to vertx event queue to make sure this will happen after response end is flushed to the client
                context.getComponent(Vertx.class).runOnContext(aVoid -> reportMetrics(context));
            }
        };
    }

    private void reportMetrics(ExecutionContext context) {
        final HttpClient httpClient = getOrCreateClient(context);

        io.vertx.core.buffer.Buffer payload = null;

        try {
            final Template template = getTemplate(configuration.getBody());
            final StringWriter writer = new StringWriter();
            final Map<String, Object> model = new HashMap<>(1);
            model.put("request", new RequestMetrics(context.request()));
            model.put("response", new ResponseMetrics(context.response(), context.request().metrics()));
            model.put("context", new AttributesBasedExecutionContext(context));
            template.process(model, writer);
            payload = io.vertx.core.buffer.Buffer.buffer(writer.toString());
        } catch (IOException | TemplateException ex) {}

        String url = context.getTemplateEngine().convert(configuration.getUrl());

        RequestOptions requestOpts = new RequestOptions().setAbsoluteURI(url).setMethod(convert(configuration.getMethod()));

        if (configuration.getHeaders() != null) {
            configuration
                .getHeaders()
                .forEach(header -> {
                    try {
                        String extValue = (header.getValue() != null) ? context.getTemplateEngine().convert(header.getValue()) : null;
                        if (extValue != null) {
                            requestOpts.putHeader(header.getName(), extValue);
                        }
                    } catch (Exception ex) {
                        // Do nothing
                    }
                });
        }

        if (payload != null) {
            if (configuration.getBody() != null && !configuration.getBody().isEmpty()) {
                requestOpts.putHeader(HttpHeaders.CONTENT_LENGTH, Integer.toString(payload.length()));
            }
        }

        Future<HttpClientRequest> reqFuture = httpClient.request(requestOpts);

        io.vertx.core.buffer.Buffer finalPayload = payload;
        reqFuture.onSuccess(request -> {
            if ((finalPayload != null)) {
                request.end(finalPayload);
            } else {
                request.end();
            }
        });
    }

    private HttpClient getOrCreateClient(ExecutionContext context) {
        if (client == null) {
            // Synchronization should not occur more than few times in case of high throughput.
            synchronized (this) {
                // Avoid create multiple clients by double checking the client nullability.
                if (client == null) {
                    client = createClient(context);
                }
            }
        }

        return client;
    }

    private HttpClient createClient(ExecutionContext context) {
        Vertx vertx = context.getComponent(Vertx.class);

        String url = context.getTemplateEngine().convert(configuration.getUrl());
        URI target = URI.create(url);

        HttpClientOptions options = new HttpClientOptions();
        if (HTTPS_SCHEME.equalsIgnoreCase(target.getScheme())) {
            options.setSsl(true).setTrustAll(true).setVerifyHost(false);
        }

        if (configuration.isUseSystemProxy()) {
            io.gravitee.node.api.configuration.Configuration nodeConfig = context.getComponent(
                io.gravitee.node.api.configuration.Configuration.class
            );
            try {
                options.setProxyOptions(VertxProxyOptionsUtils.buildProxyOptions(nodeConfig));
            } catch (IllegalStateException e) {
                LOGGER.warn(
                    "Metrics reporter requires a system proxy to be defined but some configurations are missing or not well defined: {}. Ignoring proxy",
                    e.getMessage()
                );
            }
        }

        return vertx.createHttpClient(options);
    }

    private static Configuration loadConfiguration() {
        Configuration configuration = new Configuration(Configuration.VERSION_2_3_31);
        configuration.setDefaultEncoding(Charset.defaultCharset().name());
        configuration.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
        configuration.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);

        // Ensure default value is false
        configuration.setAPIBuiltinEnabled(false);

        final DefaultObjectWrapperBuilder objectWrapperBuilder = new DefaultObjectWrapperBuilder(Configuration.VERSION_2_3_31);
        objectWrapperBuilder.setMemberAccessPolicy(LegacyDefaultMemberAccessPolicy.INSTANCE);
        configuration.setObjectWrapper(objectWrapperBuilder.build());

        // Load inline templates
        configuration.setTemplateLoader(templateLoader);

        return configuration;
    }

    Template getTemplate(String template) throws IOException {
        String hash = Sha1.sha1(template);
        templateLoader.putIfAbsent(hash, template);
        return templateConfiguration.getTemplate(hash);
    }

    private HttpMethod convert(io.gravitee.common.http.HttpMethod httpMethod) {
        switch (httpMethod) {
            case PATCH:
                return HttpMethod.PATCH;
            case POST:
                return HttpMethod.POST;
            case PUT:
                return HttpMethod.PUT;
        }

        return null;
    }
}

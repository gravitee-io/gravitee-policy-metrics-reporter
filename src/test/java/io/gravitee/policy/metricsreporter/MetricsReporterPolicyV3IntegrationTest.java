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

import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.definition.model.ExecutionMode;
import io.gravitee.policy.metricsreporter.configuration.MetricsReporterPolicyConfiguration;
import io.vertx.core.http.HttpMethod;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientRequest;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
@GatewayTest(v2ExecutionMode = ExecutionMode.V3)
class MetricsReporterPolicyV3IntegrationTest extends AbstractPolicyTest<MetricsReporterPolicy, MetricsReporterPolicyConfiguration> {

    @RegisterExtension
    static WireMockExtension metricsServer = WireMockExtension.newInstance().options(wireMockConfig().dynamicPort()).build();

    @Override
    public void configurePlaceHolderVariables(Map<String, String> variables) {
        variables.put("METRICS_SERVER", "http://localhost:" + metricsServer.getPort() + "/metrics");
    }

    @Test
    @DeployApi("/apis/metrics-reporter.json")
    void should_report_metrics(HttpClient client) {
        wiremock.stubFor(get("/endpoint").willReturn(ok("response from backend")));
        metricsServer.stubFor(post("/metrics").willReturn(ok("response from metrics server")));

        client
            .rxRequest(HttpMethod.GET, "/test")
            .flatMap(HttpClientRequest::rxSend)
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                return response.toFlowable();
            })
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .assertValue(response -> {
                assertThat(response).hasToString("response from backend");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(getRequestedFor(urlPathEqualTo("/endpoint")));

        // Metrics reported is done asynchronously, so we wait a little bit to be sure it's done
        await()
            .atMost(5, TimeUnit.SECONDS)
            .untilAsserted(() ->
                metricsServer.verify(
                    postRequestedFor(urlPathEqualTo("/metrics")).withRequestBody(
                        equalToJson(
                            """
                            {
                              "id": "static-id",
                              "method": "GET",
                              "status": "200"
                            }
                            """
                        )
                    )
                )
            );
    }
}

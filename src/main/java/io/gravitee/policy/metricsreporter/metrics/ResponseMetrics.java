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
package io.gravitee.policy.metricsreporter.metrics;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.gateway.api.Response;
import io.gravitee.reporter.api.http.Metrics;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class ResponseMetrics {

    private final Response response;
    private final Metrics metrics;

    public ResponseMetrics(Response response, Metrics metrics) {
        this.response = response;
        this.metrics = metrics;
    }

    public int getStatusCode() {
        return response.status();
    }

    public String getStatusReason() {
        return response.reason();
    }

    public HttpHeaders getHeaders() {
        return response.headers();
    }

    public long getContentLength() {
        return metrics.getResponseContentLength();
    }
}

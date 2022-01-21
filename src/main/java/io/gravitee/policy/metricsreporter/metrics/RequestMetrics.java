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

import io.gravitee.common.http.HttpMethod;
import io.gravitee.common.util.MultiValueMap;
import io.gravitee.gateway.api.Request;
import io.gravitee.reporter.api.http.Metrics;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class RequestMetrics {

    private final Request request;

    public RequestMetrics(Request request) {
        this.request = request;
    }

    public String getId() {
        return request.id();
    }

    public String getTransactionId() {
        return request.transactionId();
    }

    public HttpMethod getMethod() {
        return request.method();
    }

    public String getUri() {
        return request.uri();
    }

    public String getPath() {
        return request.path();
    }

    public String getScheme() {
        return request.scheme();
    }

    public String getRemoteAddress() {
        return request.remoteAddress();
    }

    public String getLocalAddress() {
        return request.localAddress();
    }

    public HeaderMapAdapter getHeaders() {
        return new HeaderMapAdapter(request.headers());
    }

    public MultiValueMap<String, String> getParams() {
        return request.parameters();
    }

    public long getContentLength() {
        return request.metrics().getRequestContentLength();
    }

    public Metrics getMetrics() {
        return request.metrics();
    }
}

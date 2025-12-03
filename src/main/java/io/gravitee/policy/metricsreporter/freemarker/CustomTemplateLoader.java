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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import freemarker.cache.TemplateLoader;
import java.io.Reader;
import java.io.StringReader;
import java.time.Duration;
import java.util.Objects;

// Duplicated class for now, see https://github.com/gravitee-io/issues/issues/6857
public class CustomTemplateLoader implements TemplateLoader {

    /**
     * Number of hours to keep script in cache after the last time it was accessed.
     */
    private static final int CACHE_EXPIRATION_HOURS = 1;

    /**
     * Max number of entries in the cache.
     */
    private static final int CACHE_MAXIMUM_SIZE = 1000;

    private final Cache<Object, Object> templates = CacheBuilder.newBuilder()
        .maximumSize(CACHE_MAXIMUM_SIZE)
        .expireAfterAccess(Duration.ofHours(CACHE_EXPIRATION_HOURS))
        .build();

    Cache<Object, Object> getCache() {
        return templates;
    }

    @Override
    public void closeTemplateSource(Object templateSource) {}

    @Override
    public Object findTemplateSource(String name) {
        return templates.getIfPresent(name);
    }

    @Override
    public long getLastModified(Object templateSource) {
        return ((TemplateSource) templateSource).lastModified;
    }

    @Override
    public Reader getReader(Object templateSource, String encoding) {
        return new StringReader(((TemplateSource) templateSource).templateContent);
    }

    public void putIfAbsent(String name, String templateSource) {
        if (templates.getIfPresent(name) == null) {
            templates.put(name, new TemplateSource(name, templateSource, System.currentTimeMillis()));
        }
    }

    private static class TemplateSource {

        private final String name;
        private final String templateContent;
        private final long lastModified;

        TemplateSource(String name, String templateContent, long lastModified) {
            this.name = name;
            this.templateContent = templateContent;
            this.lastModified = lastModified;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            TemplateSource that = (TemplateSource) o;
            return Objects.equals(name, that.name);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name);
        }

        @Override
        public String toString() {
            return name;
        }
    }
}

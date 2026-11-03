/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.http.impl.client;

import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

/**
 * Apache HttpClient 4.5.14 factory restricted to Basic HTTP challenge authentication for Paimon's
 * AWS SDK v1 and v2. Based on apache/httpcomponents-client, tag rel/v4.5.14, with the same package
 * and filename. Minimal clients have no authentication support. Connection management and other
 * builder defaults are unchanged.
 *
 * @since 4.3
 */
public class HttpClients {

    private HttpClients() {
        super();
    }

    /** Creates a builder for custom clients, including both bundled AWS transports. */
    public static HttpClientBuilder custom() {
        // Keep Digest and NTLM from using the MD5 service retained for checksums.
        return HttpClientBuilder.create()
                .setDefaultAuthSchemeRegistry(
                        RegistryBuilder.<AuthSchemeProvider>create()
                                .register(AuthSchemes.BASIC, new BasicSchemeFactory())
                                .build());
    }

    /** Creates a client with default configuration. */
    public static CloseableHttpClient createDefault() {
        return custom().build();
    }

    /** Creates a client with configuration based on system properties. */
    public static CloseableHttpClient createSystem() {
        return custom().useSystemProperties().build();
    }

    /** Creates a client with the most basic HTTP protocol support. */
    public static CloseableHttpClient createMinimal() {
        return new MinimalHttpClient(new PoolingHttpClientConnectionManager());
    }

    /** Creates a client with the most basic HTTP protocol support. */
    public static CloseableHttpClient createMinimal(final HttpClientConnectionManager connManager) {
        return new MinimalHttpClient(connManager);
    }
}

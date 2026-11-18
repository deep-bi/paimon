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

import org.apache.http.ConnectionReuseStrategy;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.client.AuthenticationStrategy;
import org.apache.http.client.UserTokenHandler;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ConnectionKeepAliveStrategy;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.execchain.ClientExecChain;
import org.apache.http.impl.execchain.MinimalClientExec;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpProcessorBuilder;
import org.apache.http.protocol.HttpRequestExecutor;
import org.apache.http.util.Args;

/** @since 4.3 */
public class HttpClients {

    private HttpClients() {}

    // source override for both bundled aws sdk versions
    public static HttpClientBuilder custom() {
        return builder(false);
    }

    public static CloseableHttpClient createDefault() {
        return custom().build();
    }

    public static CloseableHttpClient createSystem() {
        return custom().useSystemProperties().build();
    }

    public static CloseableHttpClient createMinimal() {
        return createMinimal(new PoolingHttpClientConnectionManager());
    }

    public static CloseableHttpClient createMinimal(HttpClientConnectionManager connManager) {
        Args.notNull(connManager, "HTTP connection manager");
        // minimal execution handles its own headers and never negotiates authentication
        return builder(true)
                .setConnectionManager(connManager)
                .setConnectionReuseStrategy(DefaultConnectionReuseStrategy.INSTANCE)
                .setRoutePlanner((target, request, context) -> new HttpRoute(target))
                .setHttpProcessor(HttpProcessorBuilder.create().build())
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .build();
    }

    private static HttpClientBuilder builder(boolean minimal) {
        return new HttpClientBuilder() {
            @Override
            protected ClientExecChain createMainExec(
                    HttpRequestExecutor requestExec,
                    HttpClientConnectionManager connManager,
                    ConnectionReuseStrategy reuseStrategy,
                    ConnectionKeepAliveStrategy keepAliveStrategy,
                    HttpProcessor proxyHttpProcessor,
                    AuthenticationStrategy targetAuthStrategy,
                    AuthenticationStrategy proxyAuthStrategy,
                    UserTokenHandler userTokenHandler) {
                // both sdks replace the executor, so wrap it after their configuration is applied
                HttpRequestExecutor executor = new TlsBasicRequestExecutor(requestExec);
                if (minimal) {
                    return new MinimalClientExec(
                            executor, connManager, reuseStrategy, keepAliveStrategy);
                }
                return super.createMainExec(
                        executor,
                        connManager,
                        reuseStrategy,
                        keepAliveStrategy,
                        proxyHttpProcessor,
                        targetAuthStrategy,
                        proxyAuthStrategy,
                        userTokenHandler);
            }
        }.setDefaultAuthSchemeRegistry(
                RegistryBuilder.<AuthSchemeProvider>create()
                        .register(AuthSchemes.BASIC, new BasicSchemeFactory())
                        .build());
    }
}

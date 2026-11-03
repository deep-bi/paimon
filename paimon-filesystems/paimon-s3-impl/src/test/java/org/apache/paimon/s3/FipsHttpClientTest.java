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

package org.apache.paimon.s3;

import com.sun.net.httpserver.HttpServer;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/** Checks authentication responses from the factory used by both bundled AWS SDKs. */
class FipsHttpClientTest {

    static Stream<Arguments> clientsAndChallenges() {
        return Stream.of("custom", "default", "system")
                .flatMap(
                        factory ->
                                Stream.of(
                                                "Basic realm=\"test\"",
                                                "Digest realm=\"test\", nonce=\"test\", algorithm=MD5, qop=\"auth\"",
                                                "Digest realm=\"test\", nonce=\"test\", algorithm=MD5-sess, qop=\"auth\"",
                                                "NTLM",
                                                "Negotiate",
                                                "Kerberos")
                                        .map(challenge -> Arguments.of(factory, challenge)));
    }

    @ParameterizedTest
    @MethodSource("clientsAndChallenges")
    void authenticationResponses(String factory, String challenge) throws Exception {
        AtomicInteger requests = new AtomicInteger();
        AtomicReference<String> authorization = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(
                "/",
                exchange -> {
                    requests.incrementAndGet();
                    String header = exchange.getRequestHeaders().getFirst("Authorization");
                    if (header == null) {
                        exchange.getResponseHeaders().add("WWW-Authenticate", challenge);
                        exchange.sendResponseHeaders(401, -1);
                    } else {
                        authorization.set(header);
                        exchange.sendResponseHeaders(200, -1);
                    }
                    exchange.close();
                });
        server.start();
        try (CloseableHttpClient client = client(factory)) {
            int port = server.getAddress().getPort();
            BasicCredentialsProvider credentials = new BasicCredentialsProvider();
            credentials.setCredentials(
                    new AuthScope("127.0.0.1", port),
                    new UsernamePasswordCredentials("user", "password"));
            HttpClientContext context = HttpClientContext.create();
            context.setCredentialsProvider(credentials);
            HttpGet request = new HttpGet("http://127.0.0.1:" + port + "/");
            request.setConfig(
                    RequestConfig.custom().setConnectTimeout(3000).setSocketTimeout(3000).build());
            try (CloseableHttpResponse response = client.execute(request, context)) {
                if (challenge.startsWith("Basic")) {
                    assertThat(response.getStatusLine().getStatusCode()).isEqualTo(200);
                    assertThat(requests.get()).isEqualTo(2);
                    assertThat(authorization.get()).isEqualTo("Basic dXNlcjpwYXNzd29yZA==");
                } else {
                    assertThat(response.getStatusLine().getStatusCode()).isEqualTo(401);
                    assertThat(requests.get()).isEqualTo(1);
                    assertThat(authorization.get()).isNull();
                }
            }
        } finally {
            server.stop(0);
        }
    }

    private static CloseableHttpClient client(String factory) {
        switch (factory) {
            case "custom":
                return HttpClients.custom().build();
            case "default":
                return HttpClients.createDefault();
            case "system":
                return HttpClients.createSystem();
            default:
                throw new IllegalArgumentException(factory);
        }
    }
}

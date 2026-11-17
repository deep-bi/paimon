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
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestExecutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.SSLException;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// checks authentication on the wire from the factory used by both bundled aws sdks
class FipsHttpClientTest {

    private static final String BASIC = "Basic dXNlcjpwYXNzd29yZA==";

    static Stream<Arguments> clientsAndChallenges() {
        return Stream.of("custom", "default", "system")
                .flatMap(
                        factory ->
                                Stream.of(
                                                "Digest realm=\"test\", nonce=\"test\", algorithm=MD5, qop=\"auth\"",
                                                "Digest realm=\"test\", nonce=\"test\", algorithm=MD5-sess, qop=\"auth\"",
                                                "NTLM",
                                                "Negotiate",
                                                "Kerberos")
                                        .map(challenge -> Arguments.of(factory, challenge)));
    }

    static Stream<Arguments> clientsAndBasicModes() {
        return Stream.of("custom", "default", "system")
                .flatMap(
                        factory ->
                                Stream.of("challenged", "cached", "manual")
                                        .map(mode -> Arguments.of(factory, mode)));
    }

    @ParameterizedTest
    @MethodSource("clientsAndChallenges")
    void unsupportedChallengesReceiveNoCredentials(String factory, String challenge)
            throws Exception {
        try (Peer peer = new Peer(false, challenge);
                CloseableHttpClient client = client(factory)) {
            try (CloseableHttpResponse response =
                    client.execute(
                            request(peer.url()),
                            context(peer.port(), "http", "NTLM".equals(challenge), false))) {
                assertThat(response.getStatusLine().getStatusCode()).isEqualTo(401);
            }
            assertThat(peer.requests.get()).isEqualTo(1);
            assertThat(peer.authenticated.get()).isZero();
        }
    }

    @ParameterizedTest
    @MethodSource("clientsAndBasicModes")
    void plaintextBasicFailsBeforeCredentialsAreSent(String factory, String mode) throws Exception {
        try (Peer peer = new Peer(false);
                CloseableHttpClient client = client(factory)) {
            assertBasicRejected(client, peer, mode);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"minimal", "minimal-manager"})
    void minimalClientsRejectManualBasicOnPlaintext(String factory) throws Exception {
        try (Peer peer = new Peer(false);
                CloseableHttpClient client = client(factory)) {
            assertBasicRejected(client, peer, "manual");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"minimal", "minimal-manager"})
    void minimalClientsDoNotNegotiateAuthentication(String factory) throws Exception {
        try (Peer peer = new Peer(false);
                CloseableHttpClient client = client(factory)) {
            try (CloseableHttpResponse response =
                    client.execute(
                            request(peer.url()), context(peer.port(), "http", false, true))) {
                assertThat(response.getStatusLine().getStatusCode()).isEqualTo(401);
            }
            assertThat(peer.requests.get()).isEqualTo(1);
            assertThat(peer.authenticated.get()).isZero();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"minimal", "minimal-manager"})
    void minimalClientsDoNotFollowRedirects(String factory) throws Exception {
        try (Peer peer = new Peer(false);
                CloseableHttpClient client = client(factory)) {
            peer.server.removeContext("/");
            peer.server.createContext(
                    "/",
                    exchange -> {
                        peer.requests.incrementAndGet();
                        exchange.getResponseHeaders().add("Location", peer.url() + "redirect");
                        exchange.sendResponseHeaders(302, -1);
                        exchange.close();
                    });
            try (CloseableHttpResponse response = client.execute(request(peer.url()))) {
                assertThat(response.getStatusLine().getStatusCode()).isEqualTo(302);
            }
            assertThat(peer.requests.get()).isEqualTo(1);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"challenged", "cached", "manual", "minimal"})
    void basicWorksOverTrustedTls(String mode) throws Exception {
        AtomicInteger delegated = new AtomicInteger();
        try (Peer peer = new Peer(true);
                CloseableHttpClient client =
                        "minimal".equals(mode)
                                ? HttpClients.createMinimal(FipsTestTls.connectionManager())
                                : HttpClients.custom()
                                        .setSSLContext(FipsTestTls.context())
                                        .setRequestExecutor(
                                                new HttpRequestExecutor() {
                                                    @Override
                                                    public HttpResponse execute(
                                                            HttpRequest request,
                                                            HttpClientConnection connection,
                                                            HttpContext context)
                                                            throws IOException, HttpException {
                                                        delegated.incrementAndGet();
                                                        return super.execute(
                                                                request, connection, context);
                                                    }
                                                })
                                        .build()) {
            HttpGet request = request(peer.url());
            if ("manual".equals(mode) || "minimal".equals(mode)) {
                request.setHeader("Authorization", BASIC);
            }
            try (CloseableHttpResponse response =
                    client.execute(
                            request, context(peer.port(), "https", false, "cached".equals(mode)))) {
                assertThat(response.getStatusLine().getStatusCode()).isEqualTo(200);
            }
            assertThat(peer.authenticated.get()).isEqualTo(1);
            int expectedRequests = "challenged".equals(mode) ? 2 : 1;
            assertThat(peer.requests.get()).isEqualTo(expectedRequests);
            if (!"minimal".equals(mode)) {
                assertThat(delegated.get()).isEqualTo(expectedRequests);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"untrusted", "hostname"})
    void tlsVerificationStillRejectsInvalidPeers(String failure) throws Exception {
        try (Peer peer = new Peer(true);
                CloseableHttpClient client =
                        "hostname".equals(failure)
                                ? HttpClients.custom().setSSLContext(FipsTestTls.context()).build()
                                : HttpClients.createDefault()) {
            HttpGet request =
                    request(
                            "hostname".equals(failure)
                                    ? peer.url().replace("localhost", "127.0.0.1")
                                    : peer.url());
            request.setHeader("Authorization", BASIC);
            assertThatThrownBy(() -> client.execute(request)).isInstanceOf(SSLException.class);
            assertThat(peer.requests.get()).isZero();
        }
    }

    @Test
    void httpsRedirectCannotSendManualBasicOverPlaintext() throws Exception {
        try (Peer plaintext = new Peer(false);
                Peer tls = new Peer(true);
                CloseableHttpClient client =
                        HttpClients.custom().setSSLContext(FipsTestTls.context()).build()) {
            tls.server.removeContext("/");
            tls.server.createContext(
                    "/",
                    exchange -> {
                        exchange.getResponseHeaders().add("Location", plaintext.url());
                        exchange.sendResponseHeaders(302, -1);
                        exchange.close();
                    });
            HttpGet request = request(tls.url());
            request.setHeader("Authorization", BASIC);
            assertThatThrownBy(() -> client.execute(request))
                    .hasRootCauseInstanceOf(ProtocolException.class)
                    .hasStackTraceContaining("Basic authentication requires TLS");
            assertThat(plaintext.requests.get()).isZero();
        }
    }

    static Stream<Arguments> manualHeaders() {
        return Stream.of("Authorization", "Proxy-Authorization")
                .flatMap(
                        header ->
                                Stream.of(
                                                BASIC,
                                                "bAsIc dXNlcjpwYXNzd29yZA==",
                                                " \tbasic dXNlcjpwYXNzd29yZA== ")
                                        .map(value -> Arguments.of(header, value)));
    }

    @ParameterizedTest
    @MethodSource("manualHeaders")
    void allManualHeadersAreCheckedAfterCustomInterceptors(String header, String value)
            throws Exception {
        try (Peer peer = new Peer(false);
                CloseableHttpClient client =
                        HttpClients.custom()
                                .setRequestExecutor(new HttpRequestExecutor())
                                .addInterceptorLast(
                                        (org.apache.http.HttpRequestInterceptor)
                                                (request, context) -> {
                                                    request.addHeader(
                                                            header,
                                                            "AWS4-HMAC-SHA256 test-signature");
                                                    request.addHeader(header, value);
                                                })
                                .build()) {
            assertThatThrownBy(() -> client.execute(request(peer.url())))
                    .hasRootCauseInstanceOf(ProtocolException.class)
                    .hasStackTraceContaining("Basic authentication requires TLS");
            assertThat(peer.requests.get()).isZero();
        }
    }

    @Test
    void proxyCredentialsCannotBeSentToAnHttpsOrigin() throws Exception {
        try (Peer peer = new Peer(true);
                CloseableHttpClient client =
                        HttpClients.custom().setSSLContext(FipsTestTls.context()).build()) {
            HttpGet request = request(peer.url());
            request.setHeader("Proxy-Authorization", BASIC);
            assertThatThrownBy(() -> client.execute(request))
                    .hasRootCauseInstanceOf(ProtocolException.class);
            assertThat(peer.requests.get()).isZero();
        }
    }

    private static void assertBasicRejected(CloseableHttpClient client, Peer peer, String mode) {
        HttpGet request = request(peer.url());
        if ("manual".equals(mode)) {
            request.setHeader("Authorization", BASIC);
        }
        assertThatThrownBy(
                        () ->
                                client.execute(
                                        request,
                                        context(peer.port(), "http", false, "cached".equals(mode))))
                .hasRootCauseInstanceOf(ProtocolException.class)
                .hasStackTraceContaining("Basic authentication requires TLS");
        assertThat(peer.requests.get()).isEqualTo("challenged".equals(mode) ? 1 : 0);
        assertThat(peer.authenticated.get()).isZero();
    }

    private static HttpClientContext context(
            int port, String scheme, boolean ntlm, boolean cached) {
        BasicCredentialsProvider credentials = new BasicCredentialsProvider();
        credentials.setCredentials(
                new AuthScope("localhost", port),
                ntlm
                        ? new NTCredentials("user", "password", "workstation", "domain")
                        : new UsernamePasswordCredentials("user", "password"));
        HttpClientContext context = HttpClientContext.create();
        context.setCredentialsProvider(credentials);
        if (cached) {
            BasicAuthCache cache = new BasicAuthCache();
            cache.put(new HttpHost("localhost", port, scheme), new BasicScheme());
            context.setAuthCache(cache);
        }
        return context;
    }

    private static HttpGet request(String url) {
        HttpGet request = new HttpGet(url);
        request.setConfig(
                RequestConfig.custom().setConnectTimeout(3000).setSocketTimeout(3000).build());
        return request;
    }

    private static CloseableHttpClient client(String factory) {
        switch (factory) {
            case "custom":
                return HttpClients.custom().build();
            case "default":
                return HttpClients.createDefault();
            case "system":
                return HttpClients.createSystem();
            case "minimal":
                return HttpClients.createMinimal();
            case "minimal-manager":
                return HttpClients.createMinimal(new PoolingHttpClientConnectionManager());
            default:
                throw new IllegalArgumentException(factory);
        }
    }

    private static final class Peer implements AutoCloseable {
        private final HttpServer server;
        private final boolean tls;
        private final AtomicInteger requests = new AtomicInteger();
        private final AtomicInteger authenticated = new AtomicInteger();

        private Peer(boolean tls) throws Exception {
            this(tls, "Basic realm=\"test\"");
        }

        private Peer(boolean tls, String challenge) throws Exception {
            this.tls = tls;
            InetSocketAddress address = new InetSocketAddress("127.0.0.1", 0);
            if (tls) {
                HttpsServer https = HttpsServer.create(address, 0);
                https.setHttpsConfigurator(new HttpsConfigurator(FipsTestTls.context()));
                server = https;
            } else {
                server = HttpServer.create(address, 0);
            }
            server.createContext(
                    "/",
                    exchange -> {
                        requests.incrementAndGet();
                        exchange.getResponseHeaders().add("Connection", "close");
                        if (exchange.getRequestHeaders().getFirst("Authorization") == null) {
                            exchange.getResponseHeaders().add("WWW-Authenticate", challenge);
                            exchange.sendResponseHeaders(401, -1);
                        } else {
                            authenticated.incrementAndGet();
                            exchange.sendResponseHeaders(200, -1);
                        }
                        exchange.close();
                    });
            server.start();
        }

        private int port() {
            return server.getAddress().getPort();
        }

        private String url() {
            return (tls ? "https" : "http") + "://localhost:" + port() + "/";
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}

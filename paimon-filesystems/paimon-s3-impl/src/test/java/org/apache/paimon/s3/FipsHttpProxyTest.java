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

import org.apache.http.HttpHost;
import org.apache.http.ProtocolException;
import org.apache.http.auth.AuthScope;
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
import org.apache.http.message.BasicHeader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// distinguishes tls to an origin from tls to the proxy receiving basic credentials
class FipsHttpProxyTest {
    private static final String BASIC = "Basic dXNlcjpwYXNzd29yZA==";

    @ParameterizedTest
    @ValueSource(strings = {"challenged", "cached", "manual"})
    void basicProxyAuthenticationWorksOverTls(String mode) throws Exception {
        try (ProxyPeer proxy = new ProxyPeer(true, true);
                CloseableHttpClient client = client(proxy)) {
            HttpGet request = new HttpGet("http://origin.example.invalid/");
            if ("manual".equals(mode)) {
                request.setHeader("Proxy-Authorization", BASIC);
            }
            try (CloseableHttpResponse response = client.execute(request, context(proxy, mode))) {
                assertThat(response.getStatusLine().getStatusCode()).isEqualTo(200);
            }
            assertThat(proxy.requests).hasSize("challenged".equals(mode) ? 2 : 1);
            assertThat(proxy.requests.get(proxy.requests.size() - 1))
                    .contains("Proxy-Authorization: " + BASIC);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"challenged", "cached"})
    void basicConnectAuthenticationWorksOverTlsToProxy(String mode) throws Exception {
        try (ProxyPeer proxy = new ProxyPeer(true, true);
                CloseableHttpClient client = client(proxy)) {
            try (CloseableHttpResponse response =
                    client.execute(new HttpGet("https://localhost/"), context(proxy, mode))) {
                assertThat(response.getStatusLine().getStatusCode()).isEqualTo(200);
            }
            assertThat(proxy.requests).hasSize("challenged".equals(mode) ? 3 : 2);
            List<String> connect = proxy.requests.get(proxy.requests.size() - 2);
            assertThat(connect.get(0)).startsWith("CONNECT ");
            assertThat(connect).contains("Proxy-Authorization: " + BASIC);
            // proxy credentials must not be forwarded through the tunnel to the origin
            assertThat(proxy.requests.get(proxy.requests.size() - 1))
                    .noneMatch(line -> line.startsWith("Proxy-Authorization:"));
        }
    }

    @Test
    void originBasicWorksInsideTlsTunnelThroughPlaintextProxy() throws Exception {
        try (ProxyPeer proxy = new ProxyPeer(false, false);
                CloseableHttpClient client = client(proxy)) {
            HttpGet request = new HttpGet("https://localhost/");
            request.setHeader("Authorization", BASIC);
            try (CloseableHttpResponse response = client.execute(request)) {
                assertThat(response.getStatusLine().getStatusCode()).isEqualTo(200);
            }
            assertThat(proxy.requests).hasSize(2);
            assertThat(proxy.requests.get(0).get(0)).startsWith("CONNECT ");
            assertThat(proxy.requests.get(0)).noneMatch(line -> line.contains("Basic "));
            assertThat(proxy.requests.get(1)).contains("Authorization: " + BASIC);
        }
    }

    @Test
    void tlsToProxyDoesNotProtectBasicForPlaintextOrigin() throws Exception {
        try (ProxyPeer proxy = new ProxyPeer(true, false);
                CloseableHttpClient client = client(proxy)) {
            HttpGet request = new HttpGet("http://origin.example.invalid/");
            request.setHeader("Authorization", BASIC);
            assertThatThrownBy(() -> client.execute(request))
                    .hasRootCauseInstanceOf(ProtocolException.class)
                    .hasStackTraceContaining("Basic authentication requires TLS");
            assertThat(proxy.requests).isEmpty();
        }
    }

    private static CloseableHttpClient client(ProxyPeer proxy) throws Exception {
        return HttpClients.custom()
                .setSSLContext(FipsTestTls.context())
                .setProxy(proxy.host())
                .setDefaultRequestConfig(
                        RequestConfig.custom()
                                .setConnectTimeout(3000)
                                .setSocketTimeout(3000)
                                .build())
                .build();
    }

    private static HttpClientContext context(ProxyPeer proxy, String mode) throws Exception {
        HttpClientContext context = HttpClientContext.create();
        BasicCredentialsProvider credentials = new BasicCredentialsProvider();
        credentials.setCredentials(
                new AuthScope(proxy.host()), new UsernamePasswordCredentials("user", "password"));
        context.setCredentialsProvider(credentials);
        if ("cached".equals(mode)) {
            BasicScheme basic = new BasicScheme();
            basic.processChallenge(new BasicHeader("Proxy-Authenticate", "Basic realm=\"test\""));
            BasicAuthCache cache = new BasicAuthCache();
            cache.put(proxy.host(), basic);
            context.setAuthCache(cache);
        }
        return context;
    }

    // terminates the origin tls layer too, so tests can inspect both sides of connect
    private static final class ProxyPeer implements AutoCloseable {
        private final boolean tls;
        private final boolean authenticate;
        private final SSLContext ssl;
        private final ServerSocket server;
        private final Thread worker;
        private final List<List<String>> requests = new CopyOnWriteArrayList<>();
        private final AtomicReference<Exception> failure = new AtomicReference<>();

        private ProxyPeer(boolean tls, boolean authenticate) throws Exception {
            this.tls = tls;
            this.authenticate = authenticate;
            ssl = FipsTestTls.context();
            server =
                    tls
                            ? ssl.getServerSocketFactory()
                                    .createServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
                            : new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
            server.setSoTimeout(5000);
            worker =
                    new Thread(
                            () -> {
                                try {
                                    while (!server.isClosed()) {
                                        try (Socket socket = server.accept()) {
                                            socket.setSoTimeout(5000);
                                            handle(socket);
                                        }
                                    }
                                } catch (Exception e) {
                                    if (!server.isClosed()) {
                                        failure.set(e);
                                    }
                                }
                            },
                            "fips-proxy-peer");
            worker.setDaemon(true);
            worker.start();
        }

        private HttpHost host() {
            return new HttpHost("localhost", server.getLocalPort(), tls ? "https" : "http");
        }

        private void handle(Socket socket) throws Exception {
            List<String> request = read(socket);
            if (request.isEmpty()) {
                return;
            }
            if (authenticate && !request.contains("Proxy-Authorization: " + BASIC)) {
                write(
                        socket,
                        "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                + "Proxy-Authenticate: Basic realm=\"test\"\r\n"
                                + "Content-Length: 0\r\nConnection: close\r\n\r\n");
                return;
            }
            if (request.get(0).startsWith("CONNECT ")) {
                write(socket, "HTTP/1.1 200 Connection Established\r\n\r\n");
                try (SSLSocket origin =
                        (SSLSocket)
                                ssl.getSocketFactory()
                                        .createSocket(
                                                socket,
                                                "localhost",
                                                server.getLocalPort(),
                                                false)) {
                    origin.setUseClientMode(false);
                    origin.setSoTimeout(5000);
                    origin.startHandshake();
                    read(origin);
                    ok(origin);
                }
            } else {
                ok(socket);
            }
        }

        private List<String> read(Socket socket) throws Exception {
            BufferedReader reader =
                    new BufferedReader(
                            new InputStreamReader(
                                    socket.getInputStream(), StandardCharsets.US_ASCII));
            List<String> lines = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                lines.add(line);
            }
            if (!lines.isEmpty()) {
                requests.add(lines);
            }
            return lines;
        }

        private static void ok(Socket socket) throws Exception {
            write(socket, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }

        private static void write(Socket socket, String response) throws Exception {
            socket.getOutputStream().write(response.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
        }

        @Override
        public void close() throws Exception {
            server.close();
            worker.join(5000);
            assertThat(worker.isAlive()).isFalse();
            assertThat(failure.get()).isNull();
        }
    }
}

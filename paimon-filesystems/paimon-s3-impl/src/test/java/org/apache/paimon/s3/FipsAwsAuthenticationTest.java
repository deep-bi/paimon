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

import com.amazonaws.AmazonServiceException;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.Protocol;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import org.apache.http.ProtocolException;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.apache.ProxyConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.S3Exception;

import javax.annotation.Nullable;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

// exercises authentication through the bundled aws sdks, including their request contexts
class FipsAwsAuthenticationTest {

    static Stream<Arguments> proxyRequests() {
        return Stream.of("v1", "v1-preemptive", "v2", "v2-preemptive")
                .flatMap(
                        sdk ->
                                Stream.of("http", "https")
                                        .flatMap(
                                                scheme ->
                                                        Stream.of(
                                                                        "Basic realm=\"test\"",
                                                                        "Digest realm=\"test\", nonce=\"test\", algorithm=MD5, qop=\"auth\"",
                                                                        "NTLM")
                                                                .map(
                                                                        challenge ->
                                                                                Arguments.of(
                                                                                        sdk, scheme,
                                                                                        challenge))));
    }

    @ParameterizedTest
    @MethodSource("proxyRequests")
    void plaintextProxyAuthenticationCannotSendCredentials(
            String sdk, String scheme, String challenge) throws Exception {
        // a raw http peer also accepts connect, which must fail before tls starts
        try (HttpPeer proxy =
                new HttpPeer(
                        "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                + "Proxy-Authenticate: "
                                + challenge
                                + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")) {
            Throwable failure =
                    catchThrowable(
                            () ->
                                    listBuckets(
                                            sdk,
                                            URI.create(scheme + "://s3.example.invalid"),
                                            proxy.uri()));
            if (sdk.endsWith("-preemptive") || challenge.startsWith("Basic")) {
                assertThat(failure)
                        .hasRootCauseInstanceOf(ProtocolException.class)
                        .hasStackTraceContaining("Basic authentication requires TLS");
            } else {
                assertThat(failure)
                        .isInstanceOfAny(AmazonServiceException.class, S3Exception.class);
                assertThat(
                                failure instanceof AmazonServiceException
                                        ? ((AmazonServiceException) failure).getStatusCode()
                                        : ((S3Exception) failure).statusCode())
                        .isEqualTo(407);
            }
            assertThat(proxy.requests).hasSize(sdk.endsWith("-preemptive") ? 0 : 1);
            if (proxy.requests.isEmpty()) {
                return;
            }
            List<String> request = proxy.requests.get(0);
            assertThat(request.get(0)).startsWith("https".equals(scheme) ? "CONNECT " : "GET ");
            assertThat(request)
                    .noneMatch(
                            line ->
                                    line.toLowerCase(Locale.ROOT)
                                            .startsWith("proxy-authorization:"));
            // older sdks put proxy credentials in the origin auth header
            // only the s3 signature is allowed here, and never on connect
            assertThat(request)
                    .filteredOn(line -> line.toLowerCase(Locale.ROOT).startsWith("authorization:"))
                    .allSatisfy(
                            line -> {
                                assertThat(scheme).isEqualTo("http");
                                assertThat(line.toLowerCase(Locale.ROOT))
                                        .startsWith("authorization: aws4-hmac-sha256 ");
                            });
        }
    }

    static Stream<Arguments> signingRequests() {
        return Stream.of("v1", "v2")
                .flatMap(sdk -> Stream.of(false, true).map(tls -> Arguments.of(sdk, tls)));
    }

    @ParameterizedTest
    @MethodSource("signingRequests")
    void awsSigningStillWorks(String sdk, boolean tls) throws Exception {
        String body =
                "<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                        + "<Owner><ID>test</ID><DisplayName>test</DisplayName></Owner>"
                        + "<Buckets/></ListAllMyBucketsResult>";
        try (HttpPeer server =
                new HttpPeer(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: "
                                + body.getBytes(StandardCharsets.UTF_8).length
                                + "\r\nConnection: close\r\n\r\n"
                                + body,
                        tls)) {
            listBuckets(sdk, server.uri(), null);
            assertThat(server.requests).hasSize(1);
            assertThat(server.requests.get(0))
                    .anyMatch(
                            line ->
                                    line.toLowerCase(Locale.ROOT)
                                            .startsWith("authorization: aws4-hmac-sha256 "));
        }
    }

    private static void listBuckets(String sdk, URI endpoint, @Nullable URI proxy)
            throws Exception {
        boolean preemptive = sdk.endsWith("-preemptive");
        if (sdk.startsWith("v1")) {
            ClientConfiguration configuration =
                    new ClientConfiguration()
                            .withConnectionTimeout(3000)
                            .withSocketTimeout(3000)
                            .withMaxErrorRetry(0)
                            .withReaper(false);
            if ("https".equals(endpoint.getScheme())) {
                configuration
                        .getApacheHttpClientConfig()
                        .setSslSocketFactory(new SSLConnectionSocketFactory(FipsTestTls.context()));
            }
            if (proxy != null) {
                configuration
                        .withProxyHost(proxy.getHost())
                        .withProxyPort(proxy.getPort())
                        .withProxyProtocol(Protocol.HTTP)
                        .withProxyUsername("proxy-user")
                        .withProxyPassword("proxy-password")
                        .withProxyDomain("domain")
                        .withProxyWorkstation("workstation")
                        .withNonProxyHosts("")
                        .withPreemptiveBasicProxyAuth(preemptive);
            }
            AmazonS3 client =
                    AmazonS3ClientBuilder.standard()
                            .withClientConfiguration(configuration)
                            .withCredentials(
                                    new AWSStaticCredentialsProvider(
                                            new BasicAWSCredentials("access-key", "secret-key")))
                            .withEndpointConfiguration(
                                    new AwsClientBuilder.EndpointConfiguration(
                                            endpoint.toString(), "us-east-1"))
                            .withPathStyleAccessEnabled(true)
                            .build();
            try {
                client.listBuckets();
            } finally {
                client.shutdown();
            }
        } else {
            ProxyConfiguration.Builder proxyConfiguration =
                    ProxyConfiguration.builder()
                            .useSystemPropertyValues(false)
                            .useEnvironmentVariableValues(false);
            if (proxy != null) {
                proxyConfiguration
                        .endpoint(proxy)
                        .username("proxy-user")
                        .password("proxy-password")
                        .ntlmDomain("domain")
                        .ntlmWorkstation("workstation")
                        .preemptiveBasicAuthenticationEnabled(preemptive);
            }
            ApacheHttpClient.Builder transport =
                    ApacheHttpClient.builder()
                            .proxyConfiguration(proxyConfiguration.build())
                            .connectionTimeout(Duration.ofSeconds(3))
                            .socketTimeout(Duration.ofSeconds(3));
            if ("https".equals(endpoint.getScheme())) {
                transport.socketFactory(new SSLConnectionSocketFactory(FipsTestTls.context()));
            }
            try (S3Client client =
                    S3Client.builder()
                            .httpClientBuilder(transport)
                            .overrideConfiguration(c -> c.retryPolicy(RetryPolicy.none()))
                            .credentialsProvider(
                                    StaticCredentialsProvider.create(
                                            AwsBasicCredentials.create("access-key", "secret-key")))
                            .region(Region.US_EAST_1)
                            .endpointOverride(endpoint)
                            .forcePathStyle(true)
                            .build()) {
                client.listBuckets();
            }
        }
    }

    private static class HttpPeer implements AutoCloseable {
        private final ServerSocket server;
        private final boolean tls;
        private final List<List<String>> requests = new CopyOnWriteArrayList<>();
        private final AtomicReference<Exception> failure = new AtomicReference<>();
        private final Thread worker;

        private HttpPeer(String response) throws Exception {
            this(response, false);
        }

        private HttpPeer(String response, boolean tls) throws Exception {
            this.tls = tls;
            server =
                    tls
                            ? FipsTestTls.context()
                                    .getServerSocketFactory()
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
                                            BufferedReader reader =
                                                    new BufferedReader(
                                                            new InputStreamReader(
                                                                    socket.getInputStream(),
                                                                    StandardCharsets.US_ASCII));
                                            List<String> lines = new ArrayList<>();
                                            String line;
                                            try {
                                                while ((line = reader.readLine()) != null
                                                        && !line.isEmpty()) {
                                                    lines.add(line);
                                                }
                                            } catch (SocketException e) {
                                                // rejected requests can reset the connection before
                                                // sending any headers
                                                if (!lines.isEmpty()) {
                                                    throw e;
                                                }
                                                continue;
                                            }
                                            if (lines.isEmpty()) {
                                                continue;
                                            }
                                            requests.add(lines);
                                            socket.getOutputStream()
                                                    .write(
                                                            response.getBytes(
                                                                    StandardCharsets.UTF_8));
                                            socket.getOutputStream().flush();
                                        }
                                    }
                                } catch (Exception e) {
                                    if (!server.isClosed()) {
                                        failure.set(e);
                                    }
                                }
                            },
                            "fips-http-peer");
            worker.setDaemon(true);
            worker.start();
        }

        private URI uri() {
            return URI.create(
                    (tls ? "https://localhost:" : "http://127.0.0.1:") + server.getLocalPort());
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

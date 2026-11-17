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

import org.apache.http.Header;
import org.apache.http.HeaderIterator;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.auth.AUTH;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.conn.routing.RouteInfo;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpRequestExecutor;

import java.io.IOException;

// checks basic authentication after headers are generated, including proxy connect requests
final class TlsBasicRequestExecutor extends HttpRequestExecutor {
    private final HttpRequestExecutor delegate;

    TlsBasicRequestExecutor(HttpRequestExecutor delegate) {
        this.delegate = delegate;
    }

    @Override
    public HttpResponse execute(
            HttpRequest request, HttpClientConnection connection, HttpContext context)
            throws IOException, HttpException {
        boolean originBasic = false;
        boolean proxyBasic = false;
        HeaderIterator headers = request.headerIterator();
        while (headers.hasNext()) {
            Header header = headers.nextHeader();
            if (AUTH.WWW_AUTH_RESP.equalsIgnoreCase(header.getName())) {
                originBasic |= isBasic(header.getValue());
            } else if (AUTH.PROXY_AUTH_RESP.equalsIgnoreCase(header.getName())) {
                proxyBasic |= isBasic(header.getValue());
            }
        }
        if (originBasic || proxyBasic) {
            requireTls(connection);
            RouteInfo route = HttpClientContext.adapt(context).getHttpRoute();
            boolean connect = "CONNECT".equalsIgnoreCase(request.getRequestLine().getMethod());
            if (route == null
                    || (originBasic && !protectsOrigin(route, connect))
                    || (proxyBasic && !protectsProxy(route, connect))) {
                throw new ProtocolException(
                        "Basic authentication requires TLS to the credential recipient. "
                                + "This route does not protect the credentials");
            }
        }
        return delegate.execute(request, connection, context);
    }

    private static void requireTls(HttpClientConnection connection) throws ProtocolException {
        if (!(connection instanceof ManagedHttpClientConnection)
                || ((ManagedHttpClientConnection) connection).getSSLSession() == null) {
            throw new ProtocolException(
                    "Basic authentication requires TLS to the credential recipient. "
                            + "No TLS session is available");
        }
    }

    private static boolean protectsOrigin(RouteInfo route, boolean connect) {
        // tls to a forwarding proxy does not protect the next hop to an http origin
        return !connect
                && "https".equalsIgnoreCase(route.getTargetHost().getSchemeName())
                && (route.getProxyHost() == null || route.isTunnelled());
    }

    private static boolean protectsProxy(RouteInfo route, boolean connect) {
        // after connect, the tls peer is the origin and must not receive proxy credentials
        return route.getProxyHost() != null
                && "https".equalsIgnoreCase(route.getProxyHost().getSchemeName())
                && (connect || !route.isTunnelled());
    }

    private static boolean isBasic(String value) {
        if (value == null) {
            return false;
        }
        int start = 0;
        while (start < value.length() && value.charAt(start) <= ' ') {
            start++;
        }
        int end = start + 5;
        return value.regionMatches(true, start, "Basic", 0, 5)
                && (value.length() == end || Character.isWhitespace(value.charAt(end)));
    }

    @Override
    public void preProcess(HttpRequest request, HttpProcessor processor, HttpContext context)
            throws IOException, HttpException {
        delegate.preProcess(request, processor, context);
    }

    @Override
    public void postProcess(HttpResponse response, HttpProcessor processor, HttpContext context)
            throws IOException, HttpException {
        delegate.postProcess(response, processor, context);
    }
}

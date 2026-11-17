<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# S3 FIPS build

`1.4.2-fips-deepbi1` is based on the DeepBI `1.4.2-deepbi3` release, commit
`4f8cacc7e`. It keeps that release's dependency fixes and AWS SDK versions.

The S3 plugin uses the host application's FIPS providers and JSSE configuration.
It does not bundle a validated cryptographic module or configure approved mode itself.

The build makes three changes:

- Excludes ordinary Bouncy Castle and WildFly OpenSSL from the shaded Hadoop and S3 dependencies.
- Limits HTTP authentication to Basic in both bundled AWS SDK versions. Digest, NTLM,
  Negotiate and Kerberos challenges get no authentication response. Basic requires TLS to
  the server or proxy receiving the credentials. Unsafe requests fail before credentials
  are sent. The check covers challenged, cached, preemptive and manual Basic headers.
  AWS signing and credential selection stay the same.
- Includes `com.starrocks.connector.share.security.FipsAwsHttpService` in the isolated plugin.
  StarRocks selects it through `software.amazon.awssdk.http.service.impl`. The plugin uses
  its own SDK interface because it cannot use the host SDK's interface class.

The Basic-only registry prevents the HTTP client from selecting authentication methods
outside this build's supported scope. Digest can use MD5, and NTLM uses MD4/MD5.
Basic only encodes credentials and relies on TLS for protection. Negotiate and Kerberos
need separate FIPS qualification before they can be enabled. This is a support policy
for this build, not a general FIPS requirement.

The limit applies to HTTP authentication in Paimon's S3 plugin, including proxy login.
S3 requests still use AWS SigV4 separately. StarRocks SQL login and authentication in
other connectors are outside this registry's scope.

Basic to an origin server requires HTTPS to that server. An unauthenticated HTTP proxy
can carry this traffic through a TLS tunnel. Basic to a proxy requires HTTPS to the proxy.
HTTPS at the destination does not protect credentials sent during a plaintext CONNECT.

The bundled SDKs can put preemptive proxy credentials in `Authorization` on CONNECT.
That header is rejected. Use challenged authentication over TLS for that case.
Certificate and hostname checks still use the configured transport. The factory does not
change TLS providers or disable certificate checks. SigV4-only HTTP requests still work.

The factory uses the same source override as `XmlResponsesSaxParser`. The shade filter
excludes the dependency's factory so our version ships in `paimon-plugin-s3`.
Downstream packaging does not need to modify the JAR.

From the repository root, use JDK 11 to build and install the artifacts consumed by StarRocks:

```sh
mvn -B -ntp -pl paimon-bundle,paimon-filesystems/paimon-s3,paimon-filesystems/paimon-oss \
  -am clean install -Dtest=FipsHttpClientTest,FipsHttpProxyTest,FipsAwsAuthenticationTest \
  -Dsurefire.failIfNoSpecifiedTests=false \
  -DfailIfNoTests=false
```

`FipsHttpClientTest` checks plaintext rejection, trusted TLS success, certificate and hostname
rejection, redirects, and manual headers. `FipsHttpProxyTest` checks TLS to the proxy and to the
origin separately, including authenticated CONNECT. `FipsAwsAuthenticationTest` checks both bundled
SDKs against plaintext proxy challenges, with preemptive authentication on and off, for HTTP
requests and HTTPS CONNECT. It also checks successful SigV4-signed requests over HTTP and HTTPS.
These loopback tests do not validate the host's FIPS providers or a live S3 deployment.

This check runs inside Paimon's isolated S3 plugin. It does not need a StarRocks integration
change. StarRocks host clients use a separate factory and need their own policy.

Publish this version through the repository's existing DeepBI release workflow before building
StarRocks on machines without the locally installed artifacts.

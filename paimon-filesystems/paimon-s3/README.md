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
- Compiles an Apache `HttpClients` factory with a Basic-only HTTP authentication
  registry for both bundled AWS SDK versions. Digest, NTLM, Negotiate and Kerberos challenges
  receive no authentication response. AWS request signing and credential selection are unchanged.
- Includes `com.starrocks.connector.share.security.FipsAwsHttpService` inside the isolated plugin.
  StarRocks selects this name through `software.amazon.awssdk.http.service.impl`. The plugin
  must implement its own SDK interface because it cannot use the host SDK's interface class.

The factory follows the source-override pattern already used for `XmlResponsesSaxParser`.
The shade filter excludes the dependency's original factory so the compiled replacement ships
in `paimon-plugin-s3`. Downstream packaging does not need to modify the JAR.

From the repository root, use JDK 11 to build and install the artifacts consumed by StarRocks:

```sh
mvn -B -ntp -pl paimon-bundle,paimon-filesystems/paimon-s3,paimon-filesystems/paimon-oss \
  -am clean install -Dtest=FipsHttpClientTest -Dsurefire.failIfNoSpecifiedTests=false \
  -DfailIfNoTests=false
```

`FipsHttpClientTest` checks Basic authentication and rejected challenges over loopback HTTP
for custom, default and system-property clients. StarRocks' dependency crypto tests also check
actual isolated AWS transports and BCJSSE with the production provider configuration, including
provider failures. These checks do not qualify a complete deployment or a live S3 connection.

Publish this version through the repository's existing DeepBI release workflow before building
StarRocks on machines without the locally installed artifacts.

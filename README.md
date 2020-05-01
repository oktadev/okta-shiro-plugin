[<img src="https://aws1.discourse-cdn.com/standard14/uploads/oktadev/original/1X/0c6402653dfb70edc661d4976a43a46f33e5e919.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![Maven Central](https://img.shields.io/maven-central/v/com.okta.shiro/okta-shiro-plugin.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.okta.shiro%22%20a%3A%22okta-shiro-plugin%22)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# Okta Shiro Plugin

* [Release status](#release-status)
* [Need help?](#need-help)
* [Getting started](#getting-started)
* [Usage guide](#usage-guide)
* [Configuration reference](#configuration-reference)
* [Building this project](#building-the-project)
* [Contributing](#contributing)

This repository contains a Shrio Realm for Okta, for use with OAuth2 Resource Servers.  This realm will validate Okta JWT access tokens.
 
We also publish these libraries for Java:
 
* [Spring Boot Integration](https://github.com/okta/okta-spring-boot/)
* [Okta JWT Verifier for Java](https://github.com/okta/okta-jwt-verifier-java)
* [Management SDK](https://github.com/okta/okta-sdk-java)
 
You can learn more on the [Okta + Java][lang-landing] page in our documentation.
 
## Release status

This library uses semantic versioning and follows Okta's [library version policy](https://developer.okta.com/code/library-versions/).

:heavy_check_mark: The current stable major version series is: 1.x

| Version | Status                    |
| ------- | ------------------------- |
| 0.x.0 | Beta |
 
The latest release can always be found on the [releases page][github-releases].
 
## Need help?
 
If you run into problems using this project, you can
 
* Ask questions on the [Okta Developer Forums][devforum]
* Post [issues][github-issues] here on GitHub (for code errors)
 
## Getting started
 
To use this Shiro (1.5+) realm you will need to include the following dependency:

For Apache Maven:

``` xml
<dependency>
    <groupId>com.okta.shiro</groupId>
    <artifactId>okta-shiro-plugin</artifactId>
    <version>${okta.shiro.version}</version>
</dependency>
```

For Gradle:

```groovy
runtime "com.okta.shiro:okta-shiro-plugin:${okta.shiro.version}"
```

### SNAPSHOT Dependencies

Snapshots are deployed off of the 'master' branch to [OSSRH](https://oss.sonatype.org/) and can be consumed using the following repository configured for Apache Maven or Gradle:

```txt
https://oss.sonatype.org/content/repositories/snapshots/
```

You'll also need:

* An Okta account, called an _organization_ (sign up for a free [developer organization](https://developer.okta.com/signup) if you need one)
* Another application configured to send access tokens to the project using this plugin.  You could use [Spring Cloud Gateway](https://developer.okta.com/blog/2020/01/08/secure-legacy-spring-cloud-gateway) 
 
## Usage guide

This plugin provides a Shiro Realm that will authenticate requests with an `Authorization: Bearer <access-token>` header.

To use the realm, first [define and configure](https://shiro.apache.org/realm.html#realm-configuration) the `OktaResourceServerRealm`

```ini
[main]
# define the realm
oktaRealm = com.okta.shiro.realm.OktaResourceServerRealm

# Set the issuer to your Okta org
oktaRealm.issuer = https://{yourOktaDomain}/oauth2/default

# Additionally, you can override the following default values
oktaRealm.audience = "api://default"
oktaRealm.groupClaim = "groups"
oktaRealm.nameClaim = "sub"

[urls]
# You must use the `authcBearer` filer to parse access token from the `Authorization` header
/** = authcBearer
```

The JWT claim information can be retrieved from the current Shiro `Subject` by casting the principal to `OktaJwtPrincipal`:

```java
import com.okta.shiro.OktaJwtPrincipal;
...

OktaJwtPrincipal jwtPrincipal = (OktaJwtPrincipal) SecurityUtils.getSubject().getPrincipal();
```

See the examples to help you get started even faster:

* [JAX-RS](https://github.com/oktadeveloper/okta-shiro-plugin/tree/master/examples/jaxrs)
* [Servlet](https://github.com/oktadeveloper/okta-shiro-plugin/tree/master/examples/servlet)

## Building the Project

In most cases, you won't need to build this project from source. If you want to build it yourself, just clone the repo and run:
 
 ```sh
./mvnw install
```
 
## Contributing
 
We're happy to accept contributions and PRs! Please see the [contribution guide](CONTRIBUTING.md) to understand how to structure a contribution.

[devforum]: https://devforum.okta.com/
[lang-landing]: https://developer.okta.com/code/java/
[github-issues]: https://github.com/oktadeveloper/okta-shiro-plugin/issues
[github-releases]: https://github.com/ooktadeveloper/okta-shiro-plugin/releases

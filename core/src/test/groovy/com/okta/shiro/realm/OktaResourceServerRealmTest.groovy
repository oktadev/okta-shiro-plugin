/*
 * Copyright 2018-Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.shiro.realm

import com.okta.jwt.AccessTokenVerifier
import com.okta.jwt.Jwt
import com.okta.jwt.JwtVerificationException
import com.okta.jwt.JwtVerifiers
import com.okta.shiro.OktaJwtPrincipal
import org.apache.shiro.authc.AuthenticationException
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.BearerToken
import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.subject.PrincipalCollection
import org.apache.shiro.subject.SimplePrincipalCollection
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.testng.PowerMockObjectFactory
import org.testng.IObjectFactory
import org.testng.annotations.ObjectFactory
import org.testng.annotations.Test

import static com.okta.shiro.Util.expect
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*
import static org.mockito.Mockito.*
import static org.powermock.api.mockito.PowerMockito.mockStatic

@PrepareForTest(JwtVerifiers)
class OktaResourceServerRealmTest {

    @ObjectFactory
    IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory()
    }

    @Test
    void createRealmNoIssuer() {
        def realm = new OktaResourceServerRealm()
        expect IllegalArgumentException,{ realm.init() }

        realm.setIssuer("https://test.example.com/issuer")
        realm.setAudience(null)
        expect IllegalArgumentException,{ realm.init() }
    }

    @Test
    void testAuthN() {
        String issuer = "https://test.example.com/issuer"
        String token = "test-token"

        Jwt jwt = mock(Jwt)
        AccessTokenVerifier verifier = mockVerifier(issuer)
        when(verifier.decode(token)).thenReturn(jwt)

        def realm = realm(issuer)

        AuthenticationInfo auth = realm.getAuthenticationInfo(new BearerToken(token))
        assertThat auth.getPrincipals().asList(), hasSize(1)
        def principal = auth.getPrincipals().getPrimaryPrincipal()
        assertThat principal, instanceOf(OktaJwtPrincipal)
        OktaJwtPrincipal jwtPrincipal = (OktaJwtPrincipal) principal
        assertThat jwtPrincipal.nameClaim, is("test-sub")
        assertThat jwtPrincipal.getJwtAccessToken(), is(jwt)
    }

    @Test
    void invalidAuthCJwt() {
        String issuer = "https://test.example.com/issuer"
        String token = "test-token"

        AccessTokenVerifier verifier = mockVerifier(issuer)
        when(verifier.decode(token)).thenThrow(new JwtVerificationException("expected test exception"))
        def realm = realm(issuer)

        expect AuthenticationException, { realm.getAuthenticationInfo(new BearerToken(token)) }
    }

    @Test
    void authzNoGroups() {

        Map claims = ["sub": "test-name"]
        Jwt jwt = mock(Jwt)
        when(jwt.getClaims()).thenReturn(claims)
        def realm = new OktaResourceServerRealm()
        PrincipalCollection principals = realm.createPrincipals(jwt)
        AuthorizationInfo authzInfo = realm.getAuthorizationInfo(principals)

        assertThat authzInfo.getRoles(), nullValue()
        assertThat authzInfo.getObjectPermissions(), nullValue()
        assertThat authzInfo.getStringPermissions(), nullValue()
    }

    @Test
    void authzGroupsClaimEmptyString() {

        Map claims = mock(Map)
        Jwt jwt = mock(Jwt)
        when(jwt.getClaims()).thenReturn(claims)
        def realm = new OktaResourceServerRealm()
        realm.setGroupClaim("")
        PrincipalCollection principals = realm.createPrincipals(jwt)
        AuthorizationInfo authzInfo = realm.getAuthorizationInfo(principals)

        assertThat authzInfo.getRoles(), nullValue()
        assertThat authzInfo.getObjectPermissions(), nullValue()
        assertThat authzInfo.getStringPermissions(), nullValue()

        verifyNoInteractions(claims)
    }

    @Test
    void authzNullPrincipals() {
        def realm = new OktaResourceServerRealm()
        assertThat realm.getAuthorizationInfo(null), nullValue()
    }

    @Test
    void authzOtherRealm() {
        def realm = new OktaResourceServerRealm()
        PrincipalCollection principals = new SimplePrincipalCollection("test-user", "test-realm")
        assertThat realm.getAuthorizationInfo(principals), nullValue()
    }

    @Test
    void authzWithGroups() {

        Map claims = ["sub": "test-name",
                      "groups": ["one", "two", "three"]]
        Jwt jwt = mock(Jwt)
        when(jwt.getClaims()).thenReturn(claims)
        def realm = new OktaResourceServerRealm()
        PrincipalCollection principals = realm.createPrincipals(jwt)
        AuthorizationInfo authzInfo = realm.doGetAuthorizationInfo(principals)

        assertThat authzInfo.getRoles(), is(["one", "two", "three"] as Set)
        assertThat authzInfo.getObjectPermissions(), nullValue()
        assertThat authzInfo.getStringPermissions(), nullValue()
    }

    private static AccessTokenVerifier mockVerifier(String issuer) {
        AccessTokenVerifier.Builder builder = mock(AccessTokenVerifier.Builder)
        AccessTokenVerifier verifier = mock(AccessTokenVerifier)
        mockStatic(JwtVerifiers)
        when(JwtVerifiers.accessTokenVerifierBuilder()).thenReturn(builder)
        when(builder.setIssuer(issuer)).thenReturn(builder)
        when(builder.setAudience("api://default")).thenReturn(builder)
        when(builder.build()).thenReturn(verifier)

        return verifier
    }

    private static OktaResourceServerRealm realm(String issuer="https://test.example.com/issuer", String nameClaim="test-sub") {
        def realm = new OktaResourceServerRealm()
        realm.setNameClaim(nameClaim)
        realm.setIssuer(issuer)
        realm.init()
        return realm
    }


}

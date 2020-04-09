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
package com.okta.shiro

import com.okta.jwt.Jwt
import org.testng.annotations.Test

import static com.okta.shiro.Util.expect
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.not
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

class OktaJwtPrincipalTest {

    @Test
    void emptyNameClaim() {
        Jwt jwt = mock(Jwt)
        expect(IllegalArgumentException, { new OktaJwtPrincipal(jwt, null) })
    }

    @Test
    void emptyJwt() {
        expect(IllegalArgumentException, { new OktaJwtPrincipal(null, "name") })
    }

    @Test
    void basicFunction() {
        def map = mock(Map)
        Jwt jwt = mock(Jwt)
        when(jwt.getClaims()).thenReturn(map)
        when(map.get("sub")).thenReturn("test-name")
        when(map.get("int")).thenReturn(1)
        def principal = new OktaJwtPrincipal(jwt, "sub")

        assertThat principal.getClaims(), is(map)
        assertThat principal.getJwtAccessToken(), is(jwt)
        assertThat principal.getName(), is("test-name")
        assertThat principal.getClaim("sub"), is("test-name")
        assertThat principal.getClaim("int"), is(1)
    }

    @Test
    void equalsTest() {
        Jwt jwt = mock(Jwt)
        def principal1 = new OktaJwtPrincipal(jwt, "sub1")
        def principal2 = new OktaJwtPrincipal(jwt, "sub2")
        def principal11 = new OktaJwtPrincipal(jwt, "sub1")

        assertThat principal1, not(principal2)
        assertThat principal1, is(principal11)
    }
}

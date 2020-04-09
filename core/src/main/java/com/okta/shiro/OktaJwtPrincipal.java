/*
 * Copyright 2020-Present Okta, Inc.
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
package com.okta.shiro;

import com.okta.jwt.Jwt;
import org.apache.shiro.util.Assert;

import java.security.Principal;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link Principal} implementation that wraps an Okta JWT access token.
 * @since 0.1.0
 */
public class OktaJwtPrincipal implements Principal {

    private final Jwt jwtAccessToken;
    private final String nameClaim;

    public OktaJwtPrincipal(Jwt jwtAccessToken, String nameClaim) {
        Assert.notNull(jwtAccessToken, "jwtAccessToken cannot be null");
        Assert.notNull(nameClaim, "nameClaim cannot be null");

        this.jwtAccessToken = jwtAccessToken;
        this.nameClaim = nameClaim;
    }

    @Override
    public String getName() {
        return (String) jwtAccessToken.getClaims().get(nameClaim);
    }

    public Jwt getJwtAccessToken() {
        return jwtAccessToken;
    }

    public <T> T getClaim(String key) {
        return (T) getClaims().get(key);
    }

    public Map<String, Object> getClaims() {
        return jwtAccessToken.getClaims();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OktaJwtPrincipal that = (OktaJwtPrincipal) o;
        return Objects.equals(jwtAccessToken, that.jwtAccessToken) &&
               Objects.equals(nameClaim, that.nameClaim);
    }

    @Override
    public int hashCode() {
        return Objects.hash(jwtAccessToken, nameClaim);
    }
}

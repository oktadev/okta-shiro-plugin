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
package com.okta.shiro.realm;

import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerificationException;
import com.okta.jwt.JwtVerifiers;
import com.okta.shiro.OktaJwtPrincipal;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.BearerToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.Assert;
import org.apache.shiro.util.StringUtils;

import java.security.Principal;
import java.util.List;

/**
 * A {@link org.apache.shiro.realm.Realm Realm} implementation that parses and validate Okta JWT Access Tokens.
 * <p>
 * <b>NOTE:</b> This realm MUST be use with the Shiro Bearer Token Filter {@code authcBearer}
 * <p>
 * This realm has the following properites:
 * <ul>
 *     <li>issuer: (required) this must be set to your Okta issuer URL, e.g. https://dev-123456.okta.com/oauth2/default</li>
 *     <li>audience: (defaults to {@code api://default}) This value must match the audience of your Authorization Server</li>
 *     <li>groupClaim: (defaults to {@code groups}) If the JWT access token has a list of strings in this claim, they will be mapped to Shiro Roles</li>
 *     <li>nameClaim: (defaults to {@code sub}) this JWT claim value will be used for the security {@link Principal#getName() principal name}</li>
 * </ul>
 *
 * @since 0.1.0
 * @see <a href="https://shiro.apache.org/web.html#default-filters">Shiro Default Filters</a>
 */
public class OktaResourceServerRealm extends AuthorizingRealm {

    private AccessTokenVerifier tokenVerifier;

    /**
     * Required: and Okta issuer URL.
     */
    private String issuer;

    /**
     * The audience of your Authorization server, this will be validated from the JWT claims.
     */
    private String audience = "api://default";

    /**
     * The name of the JWT claim that will be mapped to Shiro roles. The claim value is expected to be a list of Strings.
     */
    private String groupClaim = "groups";

    /**
     * The name of the JWT claim that will be used to map to {@link Principal#getName()}.
     */
    private String nameClaim = "sub";

    public OktaResourceServerRealm() {
        setAuthenticationTokenClass(BearerToken.class);
        setCredentialsMatcher(new AllowAllCredentialsMatcher()); // this realm will handle the credentials directly
    }

    @Override
    protected void onInit() {
        super.onInit();

        Assert.hasText(issuer, "An issuer is required for the " + getClass());
        Assert.hasText(audience, "An audience is required for the " + getClass());

        tokenVerifier = JwtVerifiers.accessTokenVerifierBuilder()
                .setIssuer(issuer)
                .setAudience(audience)
                .build();
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        BearerToken bearerToken = (BearerToken) token;
        try {
            Jwt jwtAccessToken = tokenVerifier.decode(bearerToken.getToken());
            PrincipalCollection principals = createPrincipals(jwtAccessToken);
            return new SimpleAuthenticationInfo(principals, null);

        } catch (JwtVerificationException e) {
            throw new AuthenticationException("Could not validate bearer token", e);
        }
    }

    PrincipalCollection createPrincipals(Jwt accessToken) {
        return new SimplePrincipalCollection(new OktaJwtPrincipal(accessToken, nameClaim), getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return (AuthorizationInfo) principals.fromRealm(getName()).stream()
                .map(it -> toAuthorizationInfo((OktaJwtPrincipal) it))
                .findFirst()
                .orElse(null);
    }

    AuthorizationInfo toAuthorizationInfo(OktaJwtPrincipal oktaJwtPrincipal) {
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        if (StringUtils.hasText(groupClaim)
            && oktaJwtPrincipal != null
            && oktaJwtPrincipal.getJwtAccessToken().getClaims().containsKey(groupClaim)) {

            List<String> groups = (List<String>) oktaJwtPrincipal.getJwtAccessToken().getClaims().get(groupClaim);
            groups.forEach(info::addRole);
        }
        return info;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getGroupClaim() {
        return groupClaim;
    }

    public void setGroupClaim(String groupClaim) {
        this.groupClaim = groupClaim;
    }

    public String getNameClaim() {
        return nameClaim;
    }

    public void setNameClaim(String nameClaim) {
        this.nameClaim = nameClaim;
    }
}

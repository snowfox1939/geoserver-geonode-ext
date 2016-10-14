/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.oauth2;

import java.util.Map;

import org.geoserver.ows.URLMangler;
import org.geoserver.security.GeoServerSecurityManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Alessio Fabiani, GeoSolutions S.A.S.
 *
 */
public class GeoNodeOAuth2URLMangler implements URLMangler {

    @Autowired
    GeoServerOAuth2SecurityConfiguration oauth2SecurityConfiguration;

    @Autowired
    OAuth2RestTemplate geoServerOauth2RestTemplate;
    
    private ApplicationContext context;
    
    public GeoNodeOAuth2URLMangler(GeoServerSecurityManager securityManager) {
        context = securityManager.getApplicationContext();
    }
    
    @Override
    public void mangleURL(StringBuilder baseURL, StringBuilder path, Map<String, String> kvp,
            URLType type) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        OAuth2AccessToken token = geoServerOauth2RestTemplate.getOAuth2ClientContext().getAccessToken();
        if (authentication.isAuthenticated() && token != null && token.getTokenType().equalsIgnoreCase(OAuth2AccessToken.BEARER_TYPE)) {
            kvp.put("access_token", token.getValue());
        }
    }

}

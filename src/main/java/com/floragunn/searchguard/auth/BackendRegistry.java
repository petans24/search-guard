/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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
 * 
 */

package com.floragunn.searchguard.auth;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Iterator;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.configuration.ConfigChangeListener;
import com.floragunn.searchguard.filter.SearchGuardRestFilter;
import com.floragunn.searchguard.http.XFFResolver;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

public class BackendRegistry implements ConfigChangeListener {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final SortedSet<AuthDomain> authDomains = new TreeSet<AuthDomain>();
    private volatile boolean initialized;
    private final ClusterService cse;
    private final TransportConfigUpdateAction tcua;

    @Inject
    public BackendRegistry(final RestController controller, final TransportConfigUpdateAction tcua, final ClusterService cse) {
        tcua.addConfigChangeListener("config", this);
        controller.registerFilter(new SearchGuardRestFilter(this));
        this.cse = cse;
        this.tcua = tcua;
    }

    private <T> T newInstance(final String clazz, final Settings settings) throws ClassNotFoundException, NoSuchMethodException,
    SecurityException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        final Class<T> t = (Class<T>) Class.forName(clazz);

        try {
            final Constructor<T> tctor = t.getConstructor(Settings.class);
            return tctor.newInstance(settings);
        } catch (final Exception e) {
            final Constructor<T> tctor = t.getConstructor(Settings.class, TransportConfigUpdateAction.class);
            return tctor.newInstance(settings, tcua);
        }
    }

    @Override
    public void onChange(final String event, final Settings settings) {
        authDomains.clear();

        final Map<String, Settings> dyn = settings.getGroups("searchguard.dynamic");

        for (final String ad : dyn.keySet()) {
            final Settings ads = dyn.get(ad);
            if (ads.getAsBoolean("enabled", true)) {
                try {
                    final AuthenticationBackend authenticationBackend = newInstance(
                            ads.get("authentication_backend.type", "com.floragunn.searchguard.auth.internal.InternalAuthenticationBackend"),
                            ads.getByPrefix("authentication_backend"));
                    final AuthorizationBackend authorizationBackend = newInstance(
                            ads.get("authorization_backend.type", "com.floragunn.searchguard.auth.internal.NoOpAuthorizationBackend"),
                            ads.getByPrefix("authentication_backend"));
                    final HTTPAuthenticator httpAuthenticator = newInstance(
                            ads.get("http_authenticator.type", "com.floragunn.searchguard.http.HTTPBasicAuthenticator"),
                            ads.getByPrefix("authentication_backend"));
                    authDomains.add(new AuthDomain(authenticationBackend, authorizationBackend, httpAuthenticator,
                            ads.getAsInt("order", 0), ads.getAsBoolean("roles_only", false)));
                } catch (final Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

            }

        }

        initialized = true;
    }

    @Override
    public void validate(final String event, final Settings settings) throws ElasticsearchSecurityException {
        // TODO Auto-generated method stub

    }

    /**
     * 
     * @param request
     * @param channel
     * @return The authenticated user, null means another roundtrip
     * @throws ElasticsearchSecurityException
     */
    public boolean authenticate(final RestRequest request, final RestChannel channel) throws ElasticsearchSecurityException {

        if (!isInitialized()) {
            log.warn("Not yet initialized");
            channel.sendResponse(new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE, "Not initialized"));
            return false;
        }

        request.putInContext("_sg_remote_address", XFFResolver.resolve(request));
        final User user = request.getFromContext("_sg_user");

        if (user != null) {
            if (log.isTraceEnabled()) {
                log.trace("User {} already authenticated", user.getName());
            }

            return true;
        }

        User authenticatedUser = null;

        for (final Iterator iterator = new TreeSet<AuthDomain>(authDomains).iterator(); iterator.hasNext();) {

            final AuthDomain authDomain = (AuthDomain) iterator.next();
            if (authDomain.isRolesOnly() && authenticatedUser == null) {
                log.error("Cannot do 'roles_only' for null user");
                continue;
            }
            
            log.debug("authenticatedUser {}", authenticatedUser);

            AuthCredentials ac = null;
            if (authenticatedUser == null) {
                ac = authDomain.getHttpAuthenticator().authenticate(request, channel);

                log.debug("ac {}", ac);
                
                if (ac == null) {
                    // roundtrip
                    // count?
                    return false;
                }
            }

            try {

                if (authenticatedUser == null) {
                    authenticatedUser = authDomain.getBackend().authenticate(ac);
                    log.debug("User '{}' is authenticated", authenticatedUser);
                    request.putInContext("_sg_user", authenticatedUser);
                    authDomain.getAbackend().fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), null));

                } else if (authDomain.isRolesOnly()) {
                    authDomain.getAbackend().fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), null));

                }

            } catch (final ElasticsearchSecurityException e) {
                log.info("Cannot authenticate user with ad {}, try next", authDomain.getOrder());
            }
        }

        if (authenticatedUser == null) {
            // TODO check if anonymous access is allowed
            throw new ElasticsearchSecurityException("cannot authenticate user with any one of the auth domains");
        }

        return true;
    }

    @Override
    public boolean isInitialized() {
        return initialized;
    }

    // @Override
    /*public User authenticate(TransportRequest tr, TransportChannel channel) throws UnsupportedOperationException {
        // TODO Auto-generated method stub
        return null;
    }*/

}

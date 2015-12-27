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

package com.floragunn.searchguard.configuration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.AliasesRequest;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.DocumentRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.AliasOrIndex;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.action.configupdate.TransportConfigUpdateAction;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.user.User;
import com.google.common.collect.Sets;

public class PrivilegesEvaluator implements ConfigChangeListener {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final ClusterService clusterService;
    private volatile Settings rolesMapping;
    private volatile Settings roles;
    private final ActionGroupHolder ah;

    @Inject
    public PrivilegesEvaluator(final ClusterService clusterService, final TransportConfigUpdateAction tcua, final ActionGroupHolder ah) {
        super();
        tcua.addConfigChangeListener("rolesmapping", this);
        tcua.addConfigChangeListener("roles", this);
        this.clusterService = clusterService;
        this.ah = ah;
    }

    @Override
    public void onChange(final String event, final Settings settings) {
        switch (event) {
        case "roles":
            roles = settings;
        case "rolesmapping":
            rolesMapping = settings;
        }
    }

    @Override
    public boolean isInitialized() {
        return rolesMapping != null && roles != null;
    }

    @Override
    public void validate(final String event, final Settings settings) throws ElasticsearchSecurityException {
        // TODO Auto-generated method stub

    }

    public boolean evaluate(final User user, final String action, final ActionRequest request) {
        final TransportAddress caller = request.getFromContext("_sg_remote_address");

        if (log.isDebugEnabled()) {
            log.debug("evaluate permissions for {}", user);
            log.debug("requested {} from {}", action, caller);
        }

        final ClusterState clusterState = clusterService.state();
        final MetaData metaData = clusterState.metaData();
        final Tuple<Set<String>, Set<String>> resolvedIndicesTypes = resolve(user, action, request, metaData);

        final Set<String> resolvedIndices = resolvedIndicesTypes.v1();
        final Set<String> resolvedTypes = resolvedIndicesTypes.v1();

        if (log.isDebugEnabled()) {
            log.debug("resolved indices: {}", resolvedIndices);
            log.debug("resolved types: {}", resolvedTypes);
        }

        final Set<String> userRoles = new HashSet<String>(user.getRoles());
        for (final String roleMap : rolesMapping.names()) {
            final Settings roleMapSettings = rolesMapping.getByPrefix(roleMap);
            if (WildcardMatcher.matchAny(roleMapSettings.getAsArray(".backendroles"), user.getRoles().toArray(new String[0]))) {
                userRoles.add(roleMap);
                continue;
            }

            if (WildcardMatcher.matchAny(roleMapSettings.getAsArray(".users"), user.getName())) {
                userRoles.add(roleMap);
                continue;
            }

            if (WildcardMatcher.matchAny(roleMapSettings.getAsArray(".hosts"), caller.getAddress())) {
                userRoles.add(roleMap);
                continue;
            }

            if (WildcardMatcher.matchAny(roleMapSettings.getAsArray(".hosts"), caller.getHost())) {
                userRoles.add(roleMap);
                continue;
            }

        }

        if (log.isDebugEnabled()) {
            log.debug("mapped roles: {}", userRoles);
        }

        user_role_loop: for (final Iterator iterator = userRoles.iterator(); iterator.hasNext();) {
            final String userRole = (String) iterator.next();
            final Settings rs = roles.getByPrefix(userRole);
            if (rs.names().isEmpty()) {
                continue;
            }

            if (log.isDebugEnabled()) {
                log.debug("evaluate role: {}", userRole);
            }

            final Set<String> resolvedActions = new HashSet<String>();
            final String[] actions = rs.getAsArray(".actions");

            for (int i = 0; i < actions.length; i++) {
                final String string = actions[i];
                final Set<String> groups = ah.getGroupMembers(string);
                if (groups.isEmpty()) {
                    resolvedActions.add(string);
                } else {
                    resolvedActions.addAll(groups);
                }

            }

            if (log.isDebugEnabled()) {
                log.debug("resolved actions:{}", resolvedActions);
            }

            final Map<String, Settings> in = rs.getGroups(".indices");

            if (log.isDebugEnabled()) {
                log.debug("allowed indices:{}", in.keySet());
            }
            
            if(resolvedIndices.contains("searchguard") && action.startsWith("indices:data/write")) {
                log.warn("Write access to searchguard index is not allowed for a regular user");
                return false;
            }
            
            if(resolvedIndices.contains("searchguard") || resolvedIndices.contains("_all")) {
                //log.warn("Access to searchguard index (or to all indices) is not allowed for a regualar user");
                //return false;
            }

            // TODO +index,-index, index wildcards

            if (WildcardMatcher.matchAll(in.keySet().toArray(new String[0]), resolvedIndices.toArray(new String[0]))) {

                if (!WildcardMatcher.matchAny(resolvedActions.toArray(new String[0]), action)) {
                    continue;
                }

                for (final String indi : in.keySet()) {

                    final String[] allowedTypes = rs.getAsArray(".indices." + indi, new String[0]);

                    if (log.isDebugEnabled()) {
                        log.debug("allowedTypes for '{}': {} ", indi, Arrays.toString(allowedTypes));
                    }

                    if (!WildcardMatcher.matchAll(allowedTypes, resolvedTypes.toArray(new String[0]))) {
                        if (log.isDebugEnabled()) {
                            log.debug("Not all types match");
                        }
                        continue user_role_loop;
                    }
                }

                if (log.isDebugEnabled()) {
                    log.debug("found a match for '{}', skip other roles", userRole);
                }

                return true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No index match");
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("No perm match");
        }

        return false;

    }

    private Tuple<Set<String>, Set<String>> resolve(final User user, final String action, final TransportRequest request,
            final MetaData metaData) {

        if (!(request instanceof CompositeIndicesRequest) && !(request instanceof IndicesRequest)) {
            return new Tuple<Set<String>, Set<String>>(Collections.EMPTY_SET, Collections.EMPTY_SET);
        }

        final Set<String> indices = new HashSet<String>();
        final Set<String> types = new HashSet<String>();

        if (request instanceof CompositeIndicesRequest) {
            for (final IndicesRequest indicesRequest : ((CompositeIndicesRequest) request).subRequests()) {
                final Tuple<Set<String>, Set<String>> t = resolve(user, action, indicesRequest, metaData);
                indices.addAll(t.v1());
                types.addAll(t.v2());
            }

        } else {

            final Tuple<Set<String>, Set<String>> t = resolve(user, action, (IndicesRequest) request, metaData);
            indices.addAll(t.v1());
            types.addAll(t.v2());
        }

        if (IndexNameExpressionResolver.isAllIndices(new ArrayList<String>(indices))) {
            indices.clear();
            indices.add("_all");
        }

        if (types.isEmpty()) {
            types.add("_all");
        }

        return new Tuple<Set<String>, Set<String>>(indices, types);
    }

    private Tuple<Set<String>, Set<String>> resolve(final User user, final String action, final IndicesRequest request,
            final MetaData metaData) {

        final Set<String> types = new HashSet<String>();
        final boolean isDocumentRequest = request instanceof DocumentRequest;

        if (isDocumentRequest) {
            final String type = ((DocumentRequest) request).type();
            types.add(type);
        }

        final Set<String> indices = Sets.newHashSet(request.indices());

        if (request instanceof AliasesRequest) {
            final AliasesRequest aliasesRequest = (AliasesRequest) request;
            indices.addAll(resolveAliases(Arrays.asList(aliasesRequest.aliases()), metaData));
            Collections.addAll(indices, aliasesRequest.aliases());

        }

        return new Tuple<Set<String>, Set<String>>(indices, types);
    }

    // works also with alias of an alias!
    private List<String> resolveAliases(final List<String> aliases, final MetaData metaData) {

        final List<String> result = new ArrayList<String>();

        final SortedMap<String, AliasOrIndex> lookup = metaData.getAliasAndIndexLookup();

        for (final String alias : lookup.keySet()) {

            if (aliases.contains(alias)) {
                final AliasOrIndex aoi = lookup.get(alias);

                if (!aoi.isAlias()) {
                    result.add(aoi.getIndices().get(0).getIndex());
                } else {
                    final List<IndexMetaData> is = aoi.getIndices();

                    for (final Iterator iterator = is.iterator(); iterator.hasNext();) {
                        final IndexMetaData indexMetaData = (IndexMetaData) iterator.next();
                        result.add(indexMetaData.getIndex());
                    }
                }
            }
        }
        return result;
    }
}

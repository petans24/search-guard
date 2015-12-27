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

package com.floragunn.searchguard.transport;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;

import com.floragunn.searchguard.ssl.transport.SearchGuardSSLTransportService;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.user.User;

public class SearchGuardTransportService extends SearchGuardSSLTransportService {

    protected final ESLogger log = Loggers.getLogger(this.getClass());

    @Inject
    public SearchGuardTransportService(final Settings settings, final Transport transport, final ThreadPool threadPool) {
        super(settings, transport, threadPool);
    }

    @Override
    public <T extends TransportResponse> void sendRequest(final DiscoveryNode node, final String action, final TransportRequest request,
            final TransportResponseHandler<T> handler) {
        copyUserHeader(request);
        super.sendRequest(node, action, request, handler);
    }

    @Override
    public <T extends TransportResponse> void sendRequest(final DiscoveryNode node, final String action, final TransportRequest request,
            final TransportRequestOptions options, final TransportResponseHandler<T> handler) {
        copyUserHeader(request);
        super.sendRequest(node, action, request, options, handler);
    }

    private void copyUserHeader(final TransportRequest request) {

        final User user = request.getFromContext("_sg_user");
        final String transportPrincipal = request.getFromContext("_sg_ssl_transport_principal");

        if(request.getFromContext("_sg_internal_request") == Boolean.TRUE) {
           request.putHeader("_sg_internal_request", "true");
        }
        //TODO keep original adress
        
        if (transportPrincipal != null) {
            if (log.isTraceEnabled()) {
                log.trace("Copy transportPrincipal {}", transportPrincipal);
                
            }
            request.putHeader("_sg_ssl_transport_principal_internode", Base64Helper.serializeObject(transportPrincipal));
        }

        if (user != null) {
            if (log.isTraceEnabled()) {
                log.trace("Copy user header for user {}", user);
            }
            
            request.putHeader("_sg_user_header", Base64Helper.serializeObject(user));
        } else {
            // request.putHeader("_sg_user_header",
            // Base64Helper.serializeObject(User.));
        }

    }

    @Override
    protected void addAdditionalContextValues(final String action, final TransportRequest request, final X509Certificate[] certs) throws Exception {

        boolean isInterClusterRequest = false;
        final Collection<List<?>> ianList = certs[0].getSubjectAlternativeNames();

        if (ianList != null) {
            final StringBuilder sb = new StringBuilder();

            for (final List<?> ian : ianList) {

                if (ian == null) {
                    continue;
                }

                for (final Iterator iterator = ian.iterator(); iterator.hasNext();) {
                    final int id = (int) iterator.next();
                    if (id == 0 || id == 8) {
                        sb.append(id + "::" + (String) iterator.next());
                    } else {
                        iterator.next();
                    }
                }
            }

            if (sb.indexOf("0::sg_is_server_node") >= 0 || sb.indexOf("8::1.2.3.4.5.5") >= 0) {
                isInterClusterRequest = true;
            }

        } else {
            if (log.isTraceEnabled()) {
                log.trace("No issuer alternative names (san) found");
            }
        }

        if (isInterClusterRequest) {
            if (log.isTraceEnabled() && !action.startsWith("internal:")) {
                log.trace("Is inter cluster request ({}/{}/{})", action, request.getClass(), request.remoteAddress());
            }
            request.putInContext("_sg_ssl_transport_intercluster_request", Boolean.TRUE);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Is not an inter cluster request");
            }
        }
        super.addAdditionalContextValues(action, request, certs);
    }
    
    
    @Override
    protected void messageReceivedDecorate(final TransportRequest request, final TransportRequestHandler handler, final TransportChannel transportChannel) throws Exception {
        com.floragunn.searchguard.configuration.RequestHolder context = new com.floragunn.searchguard.configuration.RequestHolder(request);
        com.floragunn.searchguard.configuration.RequestHolder.setCurrent(context);
        
        try{
        super.messageReceivedDecorate(request, handler, transportChannel);
        }finally {
            com.floragunn.searchguard.configuration.RequestHolder.removeCurrent();
        }
    }
}

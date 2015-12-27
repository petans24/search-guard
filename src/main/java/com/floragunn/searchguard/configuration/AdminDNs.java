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

import java.util.HashSet;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

public class AdminDNs {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Set<LdapName> adminDn = new HashSet<LdapName>();
    
    @Inject
    public AdminDNs(Settings settings) 
    {
        final String[] adminDnsA = settings.getAsArray("searchguard.authcz.admin_dn");

        for (int i = 0; i < adminDnsA.length; i++) {
            final String dn = adminDnsA[i];
            try {
                adminDn.add(new LdapName(dn));
            } catch (final InvalidNameException e) {
                log.error("Unable to parse admin dn {} {}",e, dn, e);
            }
        }
        
        log.debug("Loaded {} admin DN's {}",adminDn.size(),  adminDn);
    }
    
    public boolean isAdmin(String dn) {
        
        if(dn == null) return false;
        
        try {
            return isAdmin(new LdapName(dn));
        } catch (InvalidNameException e) {
           return false;
        }
    }
    
    public boolean isAdmin(LdapName dn) {
        if(dn == null) return false;
        
        return adminDn.contains(dn);
    }
}

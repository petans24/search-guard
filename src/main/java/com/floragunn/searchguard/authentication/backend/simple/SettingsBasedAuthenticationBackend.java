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

package com.floragunn.searchguard.authentication.backend.simple;

import java.util.Arrays;

import org.apache.commons.codec.digest.DigestUtils;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.NonCachingAuthenticationBackend;
import com.floragunn.searchguard.util.ConfigConstants;

public class SettingsBasedAuthenticationBackend implements NonCachingAuthenticationBackend {

    private final Settings settings;

    @Inject
    public SettingsBasedAuthenticationBackend(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public User authenticate(final com.floragunn.searchguard.authentication.AuthCredentials authCreds) throws AuthException {
        final String user = authCreds.getUsername();
        final char[] password = authCreds.getPassword();
        authCreds.clear();

        String pass = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_SETTINGSDB_USER + user, null);
        String digest = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_SETTINGSDB_DIGEST, null);
        String pass_input = String.valueOf(password);

        if (digest != null) {

            digest = digest.toLowerCase();

            switch (digest) {

                case "sha":
                case "sha1":
                    pass_input = DigestUtils.sha1Hex(pass_input);
                    break;
                case "sha256":
                    pass_input = DigestUtils.sha256Hex(pass_input);
                    break;
                case "sha384":
                    pass_input = DigestUtils.sha384Hex(pass_input);
                    break;
                case "sha512":
                    pass_input = DigestUtils.sha512Hex(pass_input);
                    break;

                default:
                    pass_input = DigestUtils.md5Hex(pass_input);
                    break;
            }

        }

        if (pass != null && pass_input.equals(pass)) {
            return new User(user);
        }

        throw new AuthException("No user " + user + " or wrong password (digest: " + (digest == null ? "plain/none" : digest) + ")");
    }

}
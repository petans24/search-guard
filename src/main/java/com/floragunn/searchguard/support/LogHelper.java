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

package com.floragunn.searchguard.support;

import org.elasticsearch.common.ContextAndHeaderHolder;

public class LogHelper {

    public static String toString(final ContextAndHeaderHolder holder) {
        final StringBuilder sb = new StringBuilder();
        sb.append("Headers:" + System.lineSeparator());
        for (final String key : holder.getHeaders()) {
            sb.append(key + "=" + holder.getHeader(key) + System.lineSeparator());
        }
        sb.append("Context:" + System.lineSeparator());
        for (final Object key : holder.getContext()) {
            sb.append(key + "=" + holder.getFromContext(key) + System.lineSeparator());
        }
        return sb.toString();
    }

}

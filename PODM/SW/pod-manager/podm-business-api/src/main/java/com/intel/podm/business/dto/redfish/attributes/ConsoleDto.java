/*
 * Copyright (c) 2016-2017 Intel Corporation
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

package com.intel.podm.business.dto.redfish.attributes;

import com.intel.podm.common.types.GeneralConnectType;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public final class ConsoleDto {
    private final Boolean serviceEnabled;
    private final Integer maxConcurrentSessions;
    private final List<GeneralConnectType> connectTypesSupported;

    private ConsoleDto(Builder builder) {
        serviceEnabled = builder.serviceEnabled;
        maxConcurrentSessions = builder.maxConcurrentSessions;
        connectTypesSupported = builder.connectTypesSupported;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public Boolean isServiceEnabled() {
        return serviceEnabled;
    }

    public Integer getMaxConcurrentSessions() {
        return maxConcurrentSessions;
    }

    public List<GeneralConnectType> getConnectTypesSupported() {
        return connectTypesSupported;
    }

    public static final class Builder {
        private Boolean serviceEnabled;
        private Integer maxConcurrentSessions;
        private List<GeneralConnectType> connectTypesSupported = new ArrayList<>();

        private Builder() {
        }

        public Builder serviceEnabled(Boolean serviceEnabled) {
            this.serviceEnabled = serviceEnabled;
            return this;
        }

        public Builder maxConcurrentSessions(Integer maxConcurrentSessions) {
            this.maxConcurrentSessions = maxConcurrentSessions;
            return this;
        }

        public Builder connectTypesSupported(Collection<GeneralConnectType> connectTypesSupported) {
            this.connectTypesSupported.addAll(connectTypesSupported);
            return this;
        }

        public ConsoleDto build() {
            return new ConsoleDto(this);
        }
    }
}

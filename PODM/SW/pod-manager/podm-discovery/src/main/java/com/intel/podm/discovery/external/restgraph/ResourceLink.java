/*
 * Copyright (c) 2015-2017 Intel Corporation
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

package com.intel.podm.discovery.external.restgraph;

import com.intel.podm.client.api.resources.ExternalServiceResource;

import java.util.Objects;

import static java.util.Objects.hash;

public final class ResourceLink {
    private final ExternalServiceResource source;
    private final ExternalServiceResource target;
    private final String name;

    public ResourceLink(ExternalServiceResource source, ExternalServiceResource target, String name) {
        this.source = source;
        this.target = target;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public ExternalServiceResource getSource() {
        return source;
    }

    public ExternalServiceResource getTarget() {
        return target;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ResourceLink)) {
            return false;
        }

        ResourceLink that = (ResourceLink) o;
        return Objects.equals(getSource(), that.getSource())
                && Objects.equals(getTarget(), that.getTarget())
                && Objects.equals(getName(), that.getName());
    }

    @Override
    public int hashCode() {
        return hash(getSource(), getTarget(), getName());
    }

    @Override
    public String toString() {
        return name + ": " + source.getClass().getSimpleName() + " -> " + target.getClass().getSimpleName();
    }
}

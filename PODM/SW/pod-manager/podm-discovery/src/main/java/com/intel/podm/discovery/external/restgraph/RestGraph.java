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
import com.intel.podm.client.api.resources.redfish.RackscaleServiceRootResource;

import java.util.Collection;
import java.util.HashSet;
import java.util.UUID;

import static java.util.Collections.unmodifiableCollection;

public final class RestGraph {
    private final HashSet<ExternalServiceResource> resources = new HashSet<>();
    private final HashSet<ResourceLink> links = new HashSet<>();

    public RestGraph(RackscaleServiceRootResource serviceRoot) {
        resources.add(serviceRoot);
    }

    public Collection<ResourceLink> getLinks() {
        return unmodifiableCollection(links);
    }

    public Collection<ExternalServiceResource> getResources() {
        return unmodifiableCollection(resources);
    }

    public void add(ResourceLink link) {
        resources.add(link.getSource());
        resources.add(link.getTarget());
        links.add(new ResourceLink(link.getSource(), link.getTarget(), link.getName()));
    }

    public void addAll(Iterable<ResourceLink> links) {
        for (ResourceLink link : links) {
            add(link);
        }
    }

    public boolean contains(ResourceLink resourceLink) {
        return links.contains(resourceLink);
    }

    public UUID findServiceUuid() {
        for (ExternalServiceResource resource : getResources()) {
            if (resource instanceof RackscaleServiceRootResource) {
                return ((RackscaleServiceRootResource) resource).getUuid();
            }
        }

        throw new IllegalStateException("uuid was not found");
    }
}

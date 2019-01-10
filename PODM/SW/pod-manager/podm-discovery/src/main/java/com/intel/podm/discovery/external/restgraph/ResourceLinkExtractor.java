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

import com.intel.podm.client.api.ExternalServiceApiReaderConnectionException;
import com.intel.podm.client.api.ExternalServiceApiReaderException;
import com.intel.podm.client.api.reader.ResourceLinks;
import com.intel.podm.client.api.reader.ResourceSupplier;
import com.intel.podm.client.api.resources.ExternalServiceResource;
import com.intel.podm.common.logger.Logger;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import java.util.HashSet;
import java.util.Set;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;


@Dependent
public class ResourceLinkExtractor {
    @Inject
    private Logger logger;

    public Set<ResourceLink> extractFrom(ExternalServiceResource resource) throws ExternalServiceApiReaderConnectionException {
        ResourceLinks links = (ResourceLinks) resource.getLinks();
        if (links == null) {
            return emptySet();
        }
        Set<ResourceLink> result = new HashSet<>();
        for (String name : links.getNames()) {
            Iterable<ExternalServiceResource> linkedResources = getResources(links, name);

            for (ExternalServiceResource linked : linkedResources) {
                result.add(new ResourceLink(resource, linked, name));
            }
        }
        return result;
    }

    private Set<ExternalServiceResource> getResources(ResourceLinks links, String name) throws ExternalServiceApiReaderConnectionException {
        Set<ExternalServiceResource> result = new HashSet<>();

        for (ResourceSupplier supplier : getSuppliers(links, name)) {
            try {
                result.add(supplier.get());
            } catch (ExternalServiceApiReaderException e) {
                handleExternalServiceApiReaderException(e);
            }
        }

        return result;
    }

    private Iterable<ResourceSupplier> getSuppliers(ResourceLinks links, String name) throws ExternalServiceApiReaderConnectionException {
        try {
            return links.get(name);
        } catch (ExternalServiceApiReaderException e) {
            handleExternalServiceApiReaderException(e);
            return emptyList();
        }
    }

    //TODO: consider changing method name
    private void handleExternalServiceApiReaderException(ExternalServiceApiReaderException e) throws ExternalServiceApiReaderConnectionException {
        if (e instanceof ExternalServiceApiReaderConnectionException) {
            throw (ExternalServiceApiReaderConnectionException) e;
        }
        logger.e("Problem while reading: {}, error: {}", e.getResourceUri(), e.getErrorResponse(), e);
    }
}

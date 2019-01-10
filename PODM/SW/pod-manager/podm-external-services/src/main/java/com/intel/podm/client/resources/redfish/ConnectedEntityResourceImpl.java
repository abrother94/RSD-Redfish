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

package com.intel.podm.client.resources.redfish;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.intel.podm.client.LinkName;
import com.intel.podm.client.OdataTypes;
import com.intel.podm.client.api.WebClient;
import com.intel.podm.client.api.reader.ResourceSupplier;
import com.intel.podm.client.api.resources.redfish.ConnectedEntityResource;
import com.intel.podm.client.api.resources.redfish.IdentifierObject;
import com.intel.podm.client.api.resources.redfish.PciIdResource;
import com.intel.podm.client.reader.ResourceLinksImpl;
import com.intel.podm.client.reader.ResourceSupplierImpl;
import com.intel.podm.client.resources.ODataId;
import com.intel.podm.client.resources.redfish.properties.IdentifierObjectImpl;
import com.intel.podm.client.resources.redfish.properties.PciIdResourceImpl;
import com.intel.podm.common.types.EntityRole;
import com.intel.podm.common.types.EntityType;

import java.net.URI;
import java.util.Set;

@OdataTypes({
    "Endpoint\\.ConnectedEntity"
})
public class ConnectedEntityResourceImpl implements ConnectedEntityResource {
    @JsonIgnore
    private WebClient webClient;

    @JsonIgnore
    private URI uri;

    @JsonProperty("EntityType")
    private EntityType entityType;

    @JsonProperty("EntityRole")
    private EntityRole entityRole;

    @JsonProperty("PciFunctionNumber")
    private Integer pciFunctionNumber;

    @JsonProperty("PciClassCode")
    private String pciClassCode;

    @JsonProperty("EntityPciId")
    private PciIdResourceImpl entityPciId;

    @JsonProperty("EntityLink")
    private ODataId entityLink;

    @JsonProperty("Identifiers")
    private Set<IdentifierObjectImpl> identifiers;

    @Override
    @LinkName("drivesInConnectedEntity")
    public ResourceSupplier getEntityLink() {
        if (entityLink == null) {
            return null;
        }
        return new ResourceSupplierImpl(webClient, entityLink.toUri());
    }

    @Override
    public EntityRole getEntityRole() {
        return entityRole;
    }

    @Override
    public EntityType getEntityType() {
        return entityType;
    }

    @Override
    public Integer getPciFunctionNumber() {
        return pciFunctionNumber;
    }

    @Override
    public String getPciClassCode() {
        return pciClassCode;
    }

    @Override
    public PciIdResource getEntityPciId() {
        return entityPciId;
    }

    @Override
    public Set<IdentifierObject> getIdentifiers() {
        return (Set) identifiers;
    }


    @Override
    public URI getUri() {
        return uri;
    }

    @Override
    public void setUri(URI uri) {
        this.uri = uri;
    }

    @Override
    public Links getLinks() {
        return new ResourceLinksImpl(this);
    }

    @Override
    public void setWebClient(WebClient webClient) {
        this.webClient = webClient;
    }
}

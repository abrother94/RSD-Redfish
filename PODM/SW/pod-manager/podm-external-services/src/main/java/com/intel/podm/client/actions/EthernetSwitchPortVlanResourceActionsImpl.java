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

package com.intel.podm.client.actions;

import com.intel.podm.client.actions.requests.CreateVlanRequestJson;
import com.intel.podm.client.api.ExternalServiceApiActionException;
import com.intel.podm.client.api.ExternalServiceApiReaderException;
import com.intel.podm.client.api.WebClient;
import com.intel.podm.client.api.actions.EthernetSwitchPortVlanResourceActions;
import com.intel.podm.client.api.resources.redfish.EthernetSwitchPortVlanResource;

import java.net.URI;

import static java.net.URI.create;

public class EthernetSwitchPortVlanResourceActionsImpl implements EthernetSwitchPortVlanResourceActions {
    private WebClient webClient;

    EthernetSwitchPortVlanResourceActionsImpl(WebClient webClient) {
        this.webClient = webClient;
    }

    @Override
    public URI createVlan(URI switchPortUri, int vlanId, boolean tagged, boolean enabled) throws ExternalServiceApiActionException {
        URI vlanCollectionUri = create(switchPortUri + "/VLANs");
        return webClient.post(vlanCollectionUri, new CreateVlanRequestJson(vlanId, tagged, enabled));
    }

    @Override
    public EthernetSwitchPortVlanResource getVlan(URI vlanUri) throws ExternalServiceApiReaderException {
        if (vlanUri == null) {
            throw new ExternalServiceApiReaderException("Could not read vlan", null);
        }

        return (EthernetSwitchPortVlanResource) webClient.get(vlanUri);
    }

    @Override
    public void deleteVlan(URI vlanUri) throws ExternalServiceApiActionException {
        webClient.delete(vlanUri);
    }

    @Override
    public void close() {
        webClient.close();
    }
}

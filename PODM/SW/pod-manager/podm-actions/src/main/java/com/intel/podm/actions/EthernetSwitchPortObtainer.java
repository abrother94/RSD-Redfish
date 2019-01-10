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

package com.intel.podm.actions;

import com.intel.podm.business.entities.dao.ExternalServiceDao;
import com.intel.podm.business.entities.redfish.EthernetSwitchPort;
import com.intel.podm.business.entities.redfish.EthernetSwitchPortVlan;
import com.intel.podm.business.entities.redfish.ExternalService;
import com.intel.podm.client.api.ExternalServiceApiReaderException;
import com.intel.podm.client.api.actions.EthernetSwitchPortResourceActions;
import com.intel.podm.client.api.actions.EthernetSwitchPortResourceActionsFactory;
import com.intel.podm.client.api.reader.ResourceSupplier;
import com.intel.podm.client.api.resources.redfish.EthernetSwitchPortResource;
import com.intel.podm.mappers.redfish.EthernetSwitchPortMapper;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.transaction.Transactional;
import java.net.URI;
import java.util.Objects;
import java.util.Set;

import static com.intel.podm.client.api.reader.ResourceSupplier.getUrisFromResources;
import static com.intel.podm.common.utils.Collector.toSingle;
import static java.net.URI.create;
import static javax.transaction.Transactional.TxType.MANDATORY;

@Dependent
@SuppressWarnings({"checkstyle:ClassFanOutComplexity"})
public class EthernetSwitchPortObtainer {
    @Inject
    private EthernetSwitchPortResourceActionsFactory actionsFactory;

    @Inject
    private EthernetSwitchPortMapper switchPortMapper;

    @Inject
    private ExternalServiceDao externalServiceDao;

    @Inject
    private EthernetSwitchPortVlanObtainer vlanObtainer;

    @Transactional(MANDATORY)
    public EthernetSwitchPort discoverPort(ExternalService service, URI portUri) throws ExternalServiceApiReaderException {
        try (EthernetSwitchPortResourceActions resourceActions = actionsFactory.create(service.getBaseUri())) {
            EthernetSwitchPortResource switchPortResource = resourceActions.getSwitchPort(portUri);
            EthernetSwitchPort targetSwitchPort = readEthernetSwitchPortResource(service, portUri, switchPortResource);
            updatePortMembers(resourceActions, switchPortResource, targetSwitchPort);

            Set<EthernetSwitchPortVlan> vlans = vlanObtainer.discoverEthernetSwitchPortVlans(service,
                    getUrisFromResources(switchPortResource.getVlans()));
            vlans.forEach(targetSwitchPort::addEthernetSwitchPortVlan);

            setPrimaryVlanInSwitchPort(switchPortResource, targetSwitchPort, vlans);

            return targetSwitchPort;
        }
    }

    private EthernetSwitchPort readEthernetSwitchPortResource(ExternalService service, URI switchPortUri,
                                                              EthernetSwitchPortResource switchPortResource) {
        URI sourceSwitchPortUri = create(switchPortUri.getPath());
        EthernetSwitchPort targetSwitchPort = externalServiceDao.findOrCreateEntity(service, sourceSwitchPortUri, EthernetSwitchPort.class);
        switchPortMapper.map(switchPortResource, targetSwitchPort);
        return targetSwitchPort;
    }

    private void updatePortMembers(EthernetSwitchPortResourceActions resourceActions, EthernetSwitchPortResource switchPortResource,
                                   EthernetSwitchPort targetSwitchPort) throws ExternalServiceApiReaderException {
        ExternalService externalService = targetSwitchPort.getService();
        Set<URI> portMemberUris = getUrisFromResources(switchPortResource.getPortMembers());
        for (URI portMemberUri: portMemberUris) {
            EthernetSwitchPort memberSwitchPort = externalServiceDao.findOrCreateEntity(externalService, portMemberUri, EthernetSwitchPort.class);
            targetSwitchPort.addPortMember(memberSwitchPort);

            EthernetSwitchPortResource memberSwitchPortResource = resourceActions.getSwitchPort(portMemberUri);
            readEthernetSwitchPortResource(externalService, portMemberUri, memberSwitchPortResource);
        }

        targetSwitchPort.uncouplePortMembers(portMember -> !portMemberUris.contains(portMember.getSourceUri()));
    }

    private void setPrimaryVlanInSwitchPort(EthernetSwitchPortResource switchPortResource, EthernetSwitchPort targetPort, Set<EthernetSwitchPortVlan> vlans)
            throws ExternalServiceApiReaderException {

        EthernetSwitchPortVlan oldPvid = targetPort.getPrimaryVlan();
        ResourceSupplier potentiallyNewPvid = switchPortResource.getPrimaryVlan();
        if (potentiallyNewPvid == null) {
            targetPort.setPrimaryVlan(null);
        } else {
            EthernetSwitchPortVlan newPrimaryVlan = vlans.stream()
                    .filter(vlan -> vlan.getSourceUri().equals(potentiallyNewPvid.getUri()))
                    .collect(toSingle());

            if (!Objects.equals(oldPvid, newPrimaryVlan)) {
                targetPort.setPrimaryVlan(newPrimaryVlan);
            }
        }
    }
}

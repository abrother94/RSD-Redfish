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

package com.intel.podm.allocation.strategy;

import com.intel.podm.allocation.mappers.ethernetinterface.EthernetInterfacesAllocationMapper;
import com.intel.podm.assembly.tasks.NodeAssemblyTask;
import com.intel.podm.assembly.tasks.VlanNodeAssemblyTaskFactory;
import com.intel.podm.business.entities.NonUniqueResultException;
import com.intel.podm.business.entities.dao.EthernetSwitchPortDao;
import com.intel.podm.business.entities.redfish.EthernetInterface;
import com.intel.podm.business.entities.redfish.EthernetSwitchPort;
import com.intel.podm.business.services.redfish.requests.RequestedNode;
import com.intel.podm.common.logger.Logger;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.transaction.Transactional;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.toList;
import static javax.transaction.Transactional.TxType.REQUIRED;

@Dependent
@Transactional(REQUIRED)
public class EthernetInterfacesAllocator {
    @Inject
    private EthernetInterfacesAllocationMapper mapper;

    @Inject
    private VlanNodeAssemblyTaskFactory taskFactory;

    @Inject
    private EthernetSwitchPortDao ethernetSwitchPortDao;

    @Inject
    private Logger logger;

    public List<NodeAssemblyTask> allocate(Collection<RequestedNode.EthernetInterface> requestedInterfaces,
                                           Collection<EthernetInterface> availableInterfaces) {
        Map<EthernetInterface, RequestedNode.EthernetInterface> mappedInterfaces = mapper.map(requestedInterfaces, availableInterfaces);

        return mappedInterfaces.entrySet().stream()
            .filter(entry -> entry.getValue().getVlans().isPresent())
            .filter(entry -> {
                EthernetSwitchPort ethernetSwitchPort = null;
                try {
                    ethernetSwitchPort = ethernetSwitchPortDao.getEnabledAndHealthyEthernetSwitchPortByNeighborMac(entry.getKey().getMacAddress());
                } catch (NonUniqueResultException e) {
                    logger.e("Could not use Ethernet Interface '{}' for allocation.", entry.getKey(), e);
                }

                return ethernetSwitchPort != null;
            })
            .map(entry -> taskFactory.createVlanCreationTask(entry.getKey(), entry.getValue()))
            .collect(toList());
    }
}

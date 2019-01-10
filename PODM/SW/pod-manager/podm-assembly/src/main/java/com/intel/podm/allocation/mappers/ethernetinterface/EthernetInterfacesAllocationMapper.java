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

package com.intel.podm.allocation.mappers.ethernetinterface;

import com.intel.podm.allocation.mappers.Sorter;
import com.intel.podm.business.entities.NonUniqueResultException;
import com.intel.podm.business.entities.dao.EthernetSwitchPortDao;
import com.intel.podm.business.entities.redfish.EthernetInterface;
import com.intel.podm.business.services.context.Context;
import com.intel.podm.business.services.redfish.requests.RequestedNode;
import com.intel.podm.common.logger.Logger;
import com.intel.podm.common.types.Id;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.util.Optional.empty;
import static java.util.Optional.of;
import static java.util.Optional.ofNullable;

@Dependent
public class EthernetInterfacesAllocationMapper {
    @Inject
    private EthernetSwitchPortDao ethernetSwitchPortDao;

    @Inject
    private Logger logger;

    public Map<EthernetInterface, RequestedNode.EthernetInterface> map(Collection<RequestedNode.EthernetInterface> requestedInterfaces,
                                                                       Collection<EthernetInterface> availableInterfaces) {
        Map<EthernetInterface, RequestedNode.EthernetInterface> mappedInterfaces = new HashMap<>();

        Collection<RequestedNode.EthernetInterface> requestedInterfacesQueue =
            Sorter.sort(requestedInterfaces,
                Sorter.contextsAscendingWhereNullsLast(), Sorter.ascendingWhereNullsFirst(RequestedNode.EthernetInterface::getSpeedMbps));
        Collection<EthernetInterface> availableInterfacesQueue =
            Sorter.sort(availableInterfaces,
                Sorter.ascendingWhereNullsLast(EthernetInterface::getId), Sorter.ascendingWhereNullsFirst(EthernetInterface::getSpeedMbps));

        for (RequestedNode.EthernetInterface requestedEthernetInterface : requestedInterfacesQueue) {
            Optional<EthernetInterface> matched = findMatchingInterface(requestedEthernetInterface, availableInterfacesQueue);
            matched.ifPresent(ethernetInterface -> mappedInterfaces.put(ethernetInterface, requestedEthernetInterface));
            matched.ifPresent(availableInterfacesQueue::remove);
        }

        return mappedInterfaces;
    }

    private Optional<EthernetInterface> findMatchingInterface(RequestedNode.EthernetInterface requestedEthernetInterface,
                                                              Collection<EthernetInterface> availableInterfacesQueue) {
        for (EthernetInterface availableInterface : availableInterfacesQueue) {
            if (idConstraintIsSatisfied(requestedEthernetInterface, availableInterface)
                && speedConstraintsAreSatisfied(requestedEthernetInterface, availableInterface)
                && vlansConstraintsAreSatisfied(requestedEthernetInterface, availableInterface)) {

                return of(availableInterface);
            }
        }

        return empty();
    }

    private boolean idConstraintIsSatisfied(RequestedNode.EthernetInterface requestedEthernetInterface, EthernetInterface availableInterface) {
        Id availableId = availableInterface.getId();
        Optional<Context> requestedAddress = ofNullable(requestedEthernetInterface.getResourceContext());

        if (!requestedAddress.isPresent()) {
            return true;
        }

        return Objects.equals(requestedAddress.get().getId(), availableId);
    }

    private boolean speedConstraintsAreSatisfied(RequestedNode.EthernetInterface requestedEthernetInterface, EthernetInterface availableInterface) {
        Optional<Integer> availableSpeed = ofNullable(availableInterface.getSpeedMbps());
        Optional<Integer> requestedSpeed = ofNullable(requestedEthernetInterface.getSpeedMbps());

        if (!requestedSpeed.isPresent()) {
            return true;
        }

        if (!availableSpeed.isPresent()) {
            return false;
        }

        return requestedSpeed.get() <= availableSpeed.get();
    }

    private boolean vlansConstraintsAreSatisfied(RequestedNode.EthernetInterface requestedEthernetInterface, EthernetInterface availableInterface) {
        if (requestedEthernetInterface.getVlans().isPresent()) {
            try {
                return ethernetSwitchPortDao.getEnabledAndHealthyEthernetSwitchPortByNeighborMac(availableInterface.getMacAddress()) != null;
            } catch (NonUniqueResultException e) {
                logger.e("Could not use Ethernet Interface '{}' for allocation.", availableInterface, e);
                return false;
            }
        }

        return true;
    }
}

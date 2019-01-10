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

package com.intel.podm.mappers.redfish;

import com.intel.podm.business.entities.redfish.EthernetSwitchPort;
import com.intel.podm.client.api.resources.redfish.EthernetSwitchPortResource;
import com.intel.podm.mappers.EntityMapper;
import com.intel.podm.mappers.subresources.IpV4AddressMapper;
import com.intel.podm.mappers.subresources.IpV6AddressMapper;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;

@Dependent
public class EthernetSwitchPortMapper extends EntityMapper<EthernetSwitchPortResource, EthernetSwitchPort> {
    @Inject
    private IpV4AddressMapper ipV4AddressMapper;
    @Inject
    private IpV6AddressMapper ipV6AddressMapper;

    public EthernetSwitchPortMapper() {
        super(EthernetSwitchPortResource.class, EthernetSwitchPort.class);
    }

    @Override
    protected void performNotAutomatedMapping(EthernetSwitchPortResource sourceSwitchPort, EthernetSwitchPort targetSourceSwitchPort) {
        super.performNotAutomatedMapping(source, target);
        ipV4AddressMapper.map(sourceSwitchPort.getIpV4Addresses(),
            targetSourceSwitchPort.getIpV4Addresses(), targetSourceSwitchPort::addIpV4Address);
        ipV6AddressMapper.map(sourceSwitchPort.getIpV6Addresses(),
            targetSourceSwitchPort.getIpV6Addresses(), targetSourceSwitchPort::addIpV6Address);
    }
}

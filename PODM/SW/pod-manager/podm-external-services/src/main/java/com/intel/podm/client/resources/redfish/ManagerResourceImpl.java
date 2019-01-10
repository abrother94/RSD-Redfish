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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.intel.podm.client.LinkName;
import com.intel.podm.client.OdataTypes;
import com.intel.podm.client.api.ExternalServiceApiReaderException;
import com.intel.podm.client.api.reader.ResourceSupplier;
import com.intel.podm.client.api.resources.redfish.ManagerResource;
import com.intel.podm.client.resources.ExternalServiceResourceImpl;
import com.intel.podm.client.resources.ODataId;
import com.intel.podm.common.types.ManagerType;
import com.intel.podm.common.types.PowerState;
import com.intel.podm.common.types.Status;
import com.intel.podm.common.types.redfish.OemType;

import java.util.List;
import java.util.UUID;

import static com.intel.podm.common.types.redfish.OemType.Type.OEM_IN_LINKS;
import static java.util.Collections.emptyList;

@OdataTypes({
    "#Manager" + OdataTypes.VERSION_PATTERN + "Manager"
})
@SuppressWarnings({"checkstyle:MethodCount"})
public class ManagerResourceImpl extends ExternalServiceResourceImpl implements ManagerResource {
    @JsonProperty("UUID")
    private UUID uuid;

    @JsonProperty("ManagerType")
    private ManagerType managerType;

    @JsonProperty("ServiceEntryPointUUID")
    private UUID serviceEntryPointUuid;

    @JsonProperty("Model")
    private String model;

    @JsonProperty("Status")
    private Status status;

    @JsonProperty("PowerState")
    private PowerState powerState;

    @JsonProperty("GraphicalConsole")
    private GraphicalConsoleObjectImpl graphicalConsole;

    @JsonProperty("SerialConsole")
    private ConsoleObjectImpl serialConsole;

    @JsonProperty("CommandShell")
    private ConsoleObjectImpl commandShell;

    @JsonProperty("FirmwareVersion")
    private String firmwareVersion;

    @JsonProperty("NetworkProtocol")
    private ODataId networkProtocol;

    @JsonProperty("EthernetInterfaces")
    private ODataId ethernetInterfaces;

    @JsonProperty("Links")
    private Links links = new Links();

    @Override
    public UUID getUuid() {
        return uuid;
    }

    @Override
    public ManagerType getManagerType() {
        return managerType;
    }

    @Override
    public UUID getServiceEntryPointUuid() {
        return serviceEntryPointUuid;
    }

    @Override
    public String getModel() {
        return model;
    }

    @Override
    public Status getStatus() {
        return status;
    }

    @Override
    public PowerState getPowerState() {
        return powerState;
    }

    @Override
    public GraphicalConsoleObjectImpl getGraphicalConsole() {
        return graphicalConsole;
    }

    @Override
    public ConsoleObjectImpl getSerialConsole() {
        return serialConsole;
    }

    @Override
    public ConsoleObjectImpl getCommandShell() {
        return commandShell;
    }

    @Override
    public String getFirmwareVersion() {
        return firmwareVersion;
    }

    @Override
    @LinkName("networkProtocol")
    public ResourceSupplier getNetworkProtocol() {
        if (networkProtocol == null) {
            return null;
        }

        return toSupplier(networkProtocol);
    }

    @Override
    @LinkName("ethernetInterfaces")
    public Iterable<ResourceSupplier> getEthernetInterfaces() throws ExternalServiceApiReaderException {
        return processMembersListResource(ethernetInterfaces);
    }

    @Override
    @LinkName("managedComputerSystems")
    public Iterable<ResourceSupplier> getManagedComputerSystems() throws ExternalServiceApiReaderException {
        return toSuppliers(links.managerForServers);
    }

    @Override
    @LinkName("managedChassisCollection")
    public Iterable<ResourceSupplier> getManagedChassisCollection() throws ExternalServiceApiReaderException {
        return toSuppliers(links.managerForChassis);
    }

    @Override
    @LinkName("managerInChassis")
    public ResourceSupplier getManagerInChassis() {
        if (links.managerInChassis == null) {
            return null;
        }
        return toSupplier(links.managerInChassis);
    }

    @Override
    @LinkName("managedEthernetSwitches")
    public Iterable<ResourceSupplier> getManagedEthernetSwitches() throws ExternalServiceApiReaderException {
        return toSuppliers(links.oem.rackScaleOem.managerForSwitches);
    }

    @Override
    @LinkName("managedServices")
    public Iterable<ResourceSupplier> getManagedServices() throws ExternalServiceApiReaderException {
        return toSuppliers(links.oem.rackScaleOem.managerForServices);
    }

    public class Links extends RedfishLinks {
        @JsonProperty("ManagerForServers")
        private List<ODataId> managerForServers;

        @JsonProperty("ManagerForChassis")
        private List<ODataId> managerForChassis;

        @JsonProperty("ManagerInChassis")
        private ODataId managerInChassis;

        @JsonProperty("Oem")
        private Oem oem = new Oem();

        @OemType(OEM_IN_LINKS)
        public class Oem extends RedfishOem {
            @JsonProperty("Intel_RackScale")
            private RackScaleOem rackScaleOem = new RackScaleOem();

            public class RackScaleOem {
                @JsonProperty("ManagerForSwitches")
                private List<ODataId> managerForSwitches;

                @JsonProperty("ManagerForServices")
                private List<ODataId> managerForServices = emptyList();
            }
        }
    }
}

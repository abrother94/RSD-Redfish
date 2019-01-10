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

package com.intel.podm.client.resources.redfish;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.intel.podm.client.LinkName;
import com.intel.podm.client.OdataTypes;
import com.intel.podm.client.api.ExternalServiceApiReaderException;
import com.intel.podm.client.api.reader.ResourceSupplier;
import com.intel.podm.client.api.resources.redfish.ComputerSystemResource;
import com.intel.podm.client.resources.ExternalServiceResourceImpl;
import com.intel.podm.client.resources.ODataId;
import com.intel.podm.common.types.DiscoveryState;
import com.intel.podm.common.types.IndicatorLed;
import com.intel.podm.common.types.PowerState;
import com.intel.podm.common.types.Ref;
import com.intel.podm.common.types.Status;
import com.intel.podm.common.types.SystemType;
import com.intel.podm.common.types.actions.ResetType;
import com.intel.podm.common.types.annotations.AsUnassigned;
import com.intel.podm.common.types.redfish.OemType;
import com.intel.podm.common.types.redfish.RedfishComputerSystem;

import java.math.BigDecimal;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static com.intel.podm.common.types.DiscoveryState.BASIC;
import static com.intel.podm.common.types.Ref.unassigned;
import static com.intel.podm.common.types.annotations.AsUnassigned.Strategy.WHEN_EMPTY_COLLECTION;
import static com.intel.podm.common.types.annotations.AsUnassigned.Strategy.WHEN_NULL;
import static com.intel.podm.common.types.redfish.OemType.Type.TOP_LEVEL_OEM;

@OdataTypes({
    "#ComputerSystem" + OdataTypes.VERSION_PATTERN + "ComputerSystem"
})
@SuppressWarnings({"checkstyle:ClassFanOutComplexity", "checkstyle:MethodCount"})
public class ComputerSystemResourceImpl extends ExternalServiceResourceImpl implements ComputerSystemResource {
    @JsonProperty("UUID")
    @AsUnassigned(WHEN_NULL)
    private Ref<UUID> uuid = unassigned();
    @JsonProperty("Manufacturer")
    @AsUnassigned(WHEN_NULL)
    private Ref<String> manufacturer = unassigned();
    @JsonProperty("Model")
    @AsUnassigned(WHEN_NULL)
    private Ref<String> model = unassigned();
    @JsonProperty("SerialNumber")
    @AsUnassigned(WHEN_NULL)
    private Ref<String> serialNumber = unassigned();
    @JsonProperty("SystemType")
    @AsUnassigned(WHEN_NULL)
    private Ref<SystemType> systemType = unassigned();
    @JsonProperty("AssetTag")
    @AsUnassigned(WHEN_NULL)
    private Ref<String> assetTag = unassigned();
    @JsonProperty("BiosVersion")
    @AsUnassigned(WHEN_NULL)
    private Ref<String> biosVersion = unassigned();
    @JsonProperty("SKU")
    @AsUnassigned(WHEN_NULL)
    private Ref<String> sku = unassigned();
    @JsonProperty("HostName")
    @AsUnassigned(WHEN_NULL)
    private Ref<String> hostName = unassigned();
    @JsonProperty("IndicatorLED")
    @AsUnassigned(WHEN_NULL)
    private Ref<IndicatorLed> indicatorLed = unassigned();
    @JsonProperty("Status")
    @AsUnassigned(WHEN_NULL)
    private Ref<Status> status = unassigned();
    @JsonProperty("PowerState")
    @AsUnassigned(WHEN_NULL)
    private Ref<PowerState> powerState = unassigned();
    @JsonProperty("PartNumber")
    @AsUnassigned(WHEN_NULL)
    private Ref<String> partNumber = unassigned();
    @JsonProperty("Memory")
    private ODataId memory;
    @JsonProperty("ProcessorSummary")
    private ProcessorSummary processorSummary = new ProcessorSummary();
    @JsonProperty("MemorySummary")
    private MemorySummary memorySummary = new MemorySummary();
    @JsonProperty("Processors")
    private ODataId processors;
    @JsonProperty("EthernetInterfaces")
    private ODataId ethernetInterfaces;
    @JsonProperty("SimpleStorage")
    private ODataId simpleStorages;
    @JsonProperty("Storage")
    private ODataId storages;
    @JsonProperty("PCIeDevices")
    private Set<ODataId> pcieDevices = new LinkedHashSet<>();
    @JsonProperty("PCIeFunctions")
    private Set<ODataId> pcieFunctions = new LinkedHashSet<>();
    @JsonProperty("Boot")
    private BootObjectImpl boot = new BootObjectImpl();
    @JsonProperty("NetworkInterfaces")
    private ODataId networkInterfaces;
    @JsonProperty("Oem")
    private Oem oem = new Oem();
    @JsonProperty("Actions")
    private Actions actions = new Actions();
    @JsonProperty("Links")
    private Links links = new Links();

    @Override
    public Ref<UUID> getUuid() {
        return uuid;
    }

    @Override
    public Ref<String> getManufacturer() {
        return manufacturer;
    }

    @Override
    public Ref<String> getModel() {
        return model;
    }

    @Override
    public Ref<String> getSerialNumber() {
        return serialNumber;
    }

    @Override
    public Ref<SystemType> getSystemType() {
        return systemType;
    }

    @Override
    public Ref<String> getAssetTag() {
        return assetTag;
    }

    @Override
    public Ref<String> getBiosVersion() {
        return biosVersion;
    }

    @Override
    public Ref<String> getSku() {
        return sku;
    }

    @Override
    public Ref<String> getHostName() {
        return hostName;
    }

    @Override
    public Ref<IndicatorLed> getIndicatorLed() {
        return indicatorLed;
    }

    @Override
    public Ref<Status> getStatus() {
        return status;
    }

    @Override
    public Ref<PowerState> getPowerState() {
        return powerState;
    }

    @Override
    public Ref<String> getPartNumber() {
        return partNumber;
    }

    @Override
    public ComputerSystemResource.Boot getBootObject() {
        return boot;
    }

    @Override
    public Ref<Integer> getMemorySockets() {
        return oem.rackScaleOem.memorySockets;
    }

    @Override
    public Ref<List<String>> getPcieConnectionId() {
        return (Ref) oem.rackScaleOem.pcieConnectionId;
    }

    @Override
    public Ref<Status> getMemoryStatus() {
        return memorySummary.status;
    }

    @Override
    public Ref<BigDecimal> getTotalSystemMemoryGiB() {
        return memorySummary.totalSystemMemoryGiB;
    }

    @Override
    public Ref<Integer> getProcessorsCount() {
        return processorSummary.count;
    }

    @Override
    public Ref<String> getProcessorModel() {
        return processorSummary.model;
    }

    @Override
    public Ref<Integer> getProcessorSockets() {
        return oem.rackScaleOem.processorSockets;
    }

    @Override
    public Ref<Status> getProcessorStatus() {
        return processorSummary.status;
    }

    @Override
    public boolean isBasic() {
        return BASIC.equals(oem.rackScaleOem.discoveryState);
    }

    @Override
    public Ref<LinkedHashSet<ResetType>> getAllowableResetTypes() {
        return actions.reset.allowableValues;
    }

    @Override
    public Ref<LinkedHashSet<RedfishComputerSystem.Device>> getPciDevices() {
        return (Ref) oem.rackScaleOem.pciDevices;
    }

    @Override
    @LinkName("storage")
    public Iterable<ResourceSupplier> getStorages() throws ExternalServiceApiReaderException {
        return processMembersListResource(storages);
    }

    @Override
    @LinkName("endpoints")
    public Iterable<ResourceSupplier> getEndpoints() throws ExternalServiceApiReaderException {
        return toSuppliers(links.endpoints);
    }

    @Override
    @LinkName("processors")
    public Iterable<ResourceSupplier> getProcessors() throws ExternalServiceApiReaderException {
        return processMembersListResource(processors);
    }

    @Override
    @LinkName("ethernetInterfaces")
    public Iterable<ResourceSupplier> getEthernetInterfaces() throws ExternalServiceApiReaderException {
        return processMembersListResource(ethernetInterfaces);
    }

    @Override
    @LinkName("memoryModules")
    public Iterable<ResourceSupplier> getMemoryModules() throws ExternalServiceApiReaderException {
        return processMembersListResource(memory);
    }

    @Override
    @LinkName("simpleStorages")
    public Iterable<ResourceSupplier> getSimpleStorages() throws ExternalServiceApiReaderException {
        return processMembersListResource(simpleStorages);
    }

    @Override
    @LinkName("pcieDevices")
    public Iterable<ResourceSupplier> getPcieDevices() throws ExternalServiceApiReaderException {
        return toSuppliers(pcieDevices);
    }

    @Override
    @LinkName("pcieFunctions")
    public Iterable<ResourceSupplier> getPcieFunctions() throws ExternalServiceApiReaderException {
        return toSuppliers(pcieFunctions);
    }

    @Override
    @LinkName("adapters")
    public Iterable<ResourceSupplier> getAdapters() throws ExternalServiceApiReaderException {
        return processMembersListResource(oem.rackScaleOem.adapters);
    }

    @Override
    @LinkName("networkInterfaces")
    public Iterable<ResourceSupplier> getNetworkInterfaces() throws ExternalServiceApiReaderException {
        return processMembersListResource(networkInterfaces);
    }

    private static class ProcessorSummary {
        @JsonProperty("Count")
        @AsUnassigned(WHEN_NULL)
        private Ref<Integer> count = unassigned();
        @JsonProperty("Model")
        @AsUnassigned(WHEN_NULL)
        private Ref<String> model = unassigned();
        @JsonProperty("Status")
        @AsUnassigned(WHEN_NULL)
        private Ref<Status> status = unassigned();
    }

    private static class MemorySummary {
        @JsonProperty("TotalSystemMemoryGiB")
        @AsUnassigned(WHEN_NULL)
        private Ref<BigDecimal> totalSystemMemoryGiB = unassigned();
        @JsonProperty("Status")
        @AsUnassigned(WHEN_NULL)
        private Ref<Status> status = unassigned();
    }

    @OemType(TOP_LEVEL_OEM)
    public class Oem extends RedfishOem {
        @JsonProperty("Intel_RackScale")
        private RackScaleOem rackScaleOem = new RackScaleOem();

        public class RackScaleOem {
            @JsonProperty("DiscoveryState")
            private DiscoveryState discoveryState;
            @JsonProperty("ProcessorSockets")
            @AsUnassigned(WHEN_NULL)
            private Ref<Integer> processorSockets = unassigned();
            @JsonProperty("MemorySockets")
            @AsUnassigned(WHEN_NULL)
            private Ref<Integer> memorySockets = unassigned();
            @JsonProperty("PciDevices")
            @AsUnassigned({WHEN_NULL, WHEN_EMPTY_COLLECTION})
            private Ref<LinkedHashSet<ComputerSystemDeviceObjectImpl>> pciDevices = unassigned();
            @JsonProperty("PCIeConnectionId")
            @AsUnassigned({WHEN_NULL, WHEN_EMPTY_COLLECTION})
            private Ref<List<String>> pcieConnectionId = unassigned();
            @JsonProperty("Adapters")
            private ODataId adapters;
        }
    }

    public class Actions extends RedfishActions {
        @JsonProperty("#ComputerSystem.Reset")
        private Reset reset = new Reset();

        public class Reset {
            @JsonProperty("ResetType@Redfish.AllowableValues")
            @AsUnassigned({WHEN_NULL, WHEN_EMPTY_COLLECTION})
            private Ref<LinkedHashSet<ResetType>> allowableValues = unassigned();
        }
    }

    public class Links extends RedfishLinks {
        @JsonProperty("Endpoints")
        private Set<ODataId> endpoints;
    }
}

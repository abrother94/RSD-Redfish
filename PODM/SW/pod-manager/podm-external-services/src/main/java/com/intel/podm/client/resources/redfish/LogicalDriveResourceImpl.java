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
import com.intel.podm.client.api.resources.redfish.LogicalDriveResource;
import com.intel.podm.client.resources.ExternalServiceResourceImpl;
import com.intel.podm.client.resources.ODataId;
import com.intel.podm.common.types.LogicalDriveType;
import com.intel.podm.common.types.Status;
import com.intel.podm.common.types.VolumeMode;

import java.math.BigDecimal;
import java.util.List;

import static com.google.common.base.MoreObjects.toStringHelper;
import static java.util.Collections.emptyList;

@OdataTypes({
    "#LogicalDrive" + OdataTypes.VERSION_PATTERN + "LogicalDrive"
})
@SuppressWarnings({"checkstyle:MethodCount"})
public class LogicalDriveResourceImpl extends ExternalServiceResourceImpl implements LogicalDriveResource {
    @JsonProperty("Type")
    private LogicalDriveType type;
    @JsonProperty("Mode")
    private VolumeMode mode;
    @JsonProperty("Protected")
    private Boolean writeProtected;
    @JsonProperty("CapacityGiB")
    private BigDecimal capacityGib;
    @JsonProperty("Image")
    private String image;
    @JsonProperty("Bootable")
    private Boolean bootable;
    @JsonProperty("Snapshot")
    private Boolean snapshot;
    @JsonProperty("Status")
    private Status status;
    @JsonProperty("Links")
    private Links links = new Links();

    @Override
    public LogicalDriveType getType() {
        return type;
    }
    @Override
    public VolumeMode getMode() {
        return mode;
    }
    @Override
    public Boolean isWriteProtected() {
        return writeProtected;
    }
    @Override
    public BigDecimal getCapacityGib() {
        return capacityGib;
    }
    @Override
    public String getImage() {
        return image;
    }
    @Override
    public Boolean isBootable() {
        return bootable;
    }
    @Override
    public Boolean isSnapshot() {
        return snapshot;
    }

    @Override
    public Status getStatus() {
        return status;
    }

    @LinkName("logicalDrives")
    @Override
    public Iterable<ResourceSupplier> getLogicalDrives() throws ExternalServiceApiReaderException {
        return toSuppliers(links.logicalDrives);
    }

    @LinkName("physicalDrives")
    @Override
    public Iterable<ResourceSupplier> getPhysicalDrives() throws ExternalServiceApiReaderException {
        return toSuppliers(links.physicalDrives);
    }

    @LinkName("masterDrive")
    @Override
    public ResourceSupplier getMasterDrive() {
        if (links.masterDrive == null) {
            return null;
        }
        return toSupplier(links.masterDrive);
    }

    @Override
    public Iterable<ResourceSupplier> getUsedBy() throws ExternalServiceApiReaderException {
        return toSuppliers(links.usedBy);
    }

    @Override
    public Iterable<ResourceSupplier> getTargets() throws ExternalServiceApiReaderException {
        return toSuppliers(links.targets);
    }

    @Override
    public String toString() {
        return toStringHelper(this)
            .add("type", type)
            .add("mode", mode)
            .add("writeProtected", writeProtected)
            .add("capacityGib", capacityGib)
            .add("image", image)
            .add("bootable", bootable)
            .add("snapshot", snapshot)
            .add("status", status)
            .add("links", links)
            .toString();
    }

    public class Links extends RedfishLinks {
        @JsonProperty("LogicalDrives")
        private List<ODataId> logicalDrives = emptyList();
        @JsonProperty("PhysicalDrives")
        private List<ODataId> physicalDrives = emptyList();
        @JsonProperty("MasterDrive")
        private ODataId masterDrive;
        @JsonProperty("UsedBy")
        private List<ODataId> usedBy = emptyList();
        @JsonProperty("Targets")
        private List<ODataId> targets = emptyList();
    }
}

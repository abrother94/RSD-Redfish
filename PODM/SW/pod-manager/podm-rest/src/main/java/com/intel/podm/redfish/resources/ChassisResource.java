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

package com.intel.podm.redfish.resources;

import com.intel.podm.business.BusinessApiException;
import com.intel.podm.business.dto.redfish.ChassisDto;
import com.intel.podm.business.services.redfish.ReaderService;
import com.intel.podm.business.services.redfish.UpdateService;
import com.intel.podm.common.types.redfish.RedfishChassis;
import com.intel.podm.redfish.json.templates.actions.ChassisPartialRepresentation;
import com.intel.podm.redfish.json.templates.actions.constraints.ChassisConstraint;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.PATCH;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import java.util.concurrent.TimeoutException;

import static com.intel.podm.business.services.context.PathParamConstants.PCIE_DEVICE_ID;
import static com.intel.podm.business.services.context.PathParamConstants.PCIE_DRIVE_ID;
import static com.intel.podm.common.types.redfish.ResourceNames.PCIE_DEVICES_RESOURCE_NAME;
import static com.intel.podm.common.types.redfish.ResourceNames.PCIE_DRIVES_RESOURCE_NAME;
import static com.intel.podm.common.types.redfish.ResourceNames.POWER_RESOURCE_NAME;
import static com.intel.podm.common.types.redfish.ResourceNames.POWER_ZONES_RESOURCE_NAME;
import static com.intel.podm.common.types.redfish.ResourceNames.THERMAL_RESOURCE_NAME;
import static com.intel.podm.common.types.redfish.ResourceNames.THERMAL_ZONES_RESOURCE_NAME;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.Response.ok;

@Produces(APPLICATION_JSON)
@SuppressWarnings({"checkstyle:ClassFanOutComplexity"})
public class ChassisResource extends BaseResource {
    @Inject
    private ReaderService<ChassisDto> readerService;

    @Inject
    private UpdateService<RedfishChassis> updateService;

    @Override
    public ChassisDto get() {
        return getOrThrow(() -> readerService.getResource(getCurrentContext()));
    }

    @Path(THERMAL_ZONES_RESOURCE_NAME)
    public ThermalZonesCollectionResource getThermalZones() {
        return getResource(ThermalZonesCollectionResource.class);
    }

    @Path(POWER_ZONES_RESOURCE_NAME)
    public PowerZonesCollectionResource getPowerZones() {
        return getResource(PowerZonesCollectionResource.class);
    }

    @Path(PCIE_DRIVES_RESOURCE_NAME + "/" + PCIE_DRIVE_ID)
    public DriveResource getPcieDrives() {
        return getResource(DriveResource.class);
    }

    @Path(PCIE_DEVICES_RESOURCE_NAME + "/" + PCIE_DEVICE_ID)
    public PcieDeviceResource getPcieDevices() {
        return getResource(PcieDeviceResource.class);
    }

    @PATCH
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    public Response updateChassis(@ChassisConstraint ChassisPartialRepresentation representation) throws TimeoutException, BusinessApiException {
        updateService.perform(getCurrentContext(), representation);
        return ok(get()).build();
    }

    @Path(THERMAL_RESOURCE_NAME)
    public ThermalResource getThermal() {
        return getResource(ThermalResource.class);
    }

    @Path(POWER_RESOURCE_NAME)
    public PowerResource getPower() {
        return getResource(PowerResource.class);
    }
}

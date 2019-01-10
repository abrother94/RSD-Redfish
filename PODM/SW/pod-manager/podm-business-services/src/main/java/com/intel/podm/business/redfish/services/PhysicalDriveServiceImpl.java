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

package com.intel.podm.business.redfish.services;

import com.intel.podm.business.ContextResolvingException;
import com.intel.podm.business.dto.redfish.CollectionDto;
import com.intel.podm.business.dto.redfish.PhysicalDriveDto;
import com.intel.podm.business.entities.redfish.PhysicalDrive;
import com.intel.podm.business.entities.redfish.StorageService;
import com.intel.podm.business.redfish.EntityTreeTraverser;
import com.intel.podm.business.redfish.services.helpers.UnknownOemTranslator;
import com.intel.podm.business.services.context.Context;
import com.intel.podm.business.services.redfish.ReaderService;

import javax.inject.Inject;
import javax.transaction.Transactional;

import static com.intel.podm.business.dto.redfish.CollectionDto.Type.PHYSICAL_DRIVES;
import static com.intel.podm.business.redfish.ContextCollections.asLogicalDriveContexts;
import static com.intel.podm.business.redfish.ContextCollections.getAsIdSet;
import static javax.transaction.Transactional.TxType.REQUIRED;

@Transactional(REQUIRED)
public class PhysicalDriveServiceImpl implements ReaderService<PhysicalDriveDto> {
    @Inject
    private EntityTreeTraverser traverser;

    @Inject
    private UnknownOemTranslator unknownOemTranslator;

    @Override
    public CollectionDto getCollection(Context serviceContext) throws ContextResolvingException {
        StorageService service = (StorageService) traverser.traverse(serviceContext);
        return new CollectionDto(PHYSICAL_DRIVES, getAsIdSet(service.getPhysicalDrives()));
    }

    @Override
    public PhysicalDriveDto getResource(Context physicalDriveContext) throws ContextResolvingException {
        PhysicalDrive drive = (PhysicalDrive) traverser.traverse(physicalDriveContext);
        return PhysicalDriveDto.newBuilder()
            .id(drive.getId().toString())
            .status(drive.getStatus())
            .description(drive.getDescription())
            .unknownOems(unknownOemTranslator.translateUnknownOemToDtos(drive.getService(), drive.getUnknownOems()))
            .capacityGib(drive.getCapacityGib())
            .controllerInterface(drive.getControllerInterface())
            .manufacturer(drive.getManufacturer())
            .model(drive.getModel())
            .serialNumber(drive.getSerialNumber())
            .name(drive.getName())
            .rpm(drive.getRpm())
            .type(drive.getType())
            .usedBy(asLogicalDriveContexts(drive.getLogicalDrives()))
            .build();
    }
}

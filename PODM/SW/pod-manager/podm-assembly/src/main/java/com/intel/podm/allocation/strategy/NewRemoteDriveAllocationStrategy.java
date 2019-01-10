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

import com.intel.podm.allocation.validation.NewRemoteDriveValidator;
import com.intel.podm.assembly.tasks.NewRemoteDriveAssemblyTask;
import com.intel.podm.assembly.tasks.NewRemoteDriveTaskFactory;
import com.intel.podm.assembly.tasks.NodeAssemblyTask;
import com.intel.podm.assembly.tasks.PatchNetworkDeviceFunctionAssemblyTaskFactory;
import com.intel.podm.business.Violations;
import com.intel.podm.business.entities.redfish.ComposedNode;
import com.intel.podm.business.services.redfish.requests.RequestedNode;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;

import static javax.transaction.Transactional.TxType.MANDATORY;

@Dependent
@Transactional(MANDATORY)
public class NewRemoteDriveAllocationStrategy implements RemoteDriveAllocationStrategy {
    @Inject
    private NewRemoteDriveValidator validator;

    @Inject
    private NewRemoteDriveResourcesFinder finder;

    @Inject
    private NewRemoteDriveTaskFactory newRemoteDriveTaskFactory;

    @Inject
    private PatchNetworkDeviceFunctionAssemblyTaskFactory networkDeviceFunctionTaskFactory;

    private RequestedNode.RemoteDrive drive;
    private NewRemoteDriveResourcesFinder.NewRemoteDriveAllocationResources resources;
    private List<NodeAssemblyTask> tasks = new ArrayList<>();

    public void setDrive(RequestedNode.RemoteDrive drive) {
        this.drive = drive;
    }

    @Override
    public Violations validate() {
        return validator.validate(drive);
    }

    @Override
    public Violations findResources() {
        resources = finder.find(drive);
        return resources.getViolations();
    }

    @Override
    public void allocate(ComposedNode composedNode) {
        reserveLvgSpace(composedNode);
        NewRemoteDriveAssemblyTask task = newRemoteDriveTaskFactory.create(resources.getLvg().getId(),
            resources.getMaster().getSourceUri(),
            drive);
        tasks.add(task);
        tasks.add(networkDeviceFunctionTaskFactory.create());
    }

    @Override
    public List<NodeAssemblyTask> getTasks() {
        return tasks;
    }

    private void reserveLvgSpace(ComposedNode composedNode) {
        composedNode.setRemoteDriveCapacityGib(resources.getCapacity());
        resources.getLvg().setComposedNode(composedNode);
    }
}

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

package com.intel.podm.assembly.tasks;

import com.intel.podm.common.enterprise.utils.logger.TimeMeasured;
import com.intel.podm.business.entities.dao.RemoteTargetDao;
import com.intel.podm.business.entities.redfish.RemoteTarget;
import com.intel.podm.common.types.Id;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.transaction.Transactional;
import java.util.UUID;

import static javax.transaction.Transactional.TxType.REQUIRES_NEW;

@Dependent
public class DeallocateRemoteTarget extends NodeAssemblyTask {

    @Inject
    private RemoteTargetDao remoteTargetDao;

    private Id remoteTargetId;

    @Override
    @Transactional(REQUIRES_NEW)
    @TimeMeasured(tag = "[AssemblyTask]")
    public void run() {
        RemoteTarget remoteTarget = remoteTargetDao.find(remoteTargetId);
        remoteTarget.getMetadata().setAllocated(false);
    }

    public DeallocateRemoteTarget setRemoteTargetId(Id remoteTargetId) {
        this.remoteTargetId = remoteTargetId;
        return this;
    }

    @Override
    @Transactional(REQUIRES_NEW)
    public UUID getServiceUuid() {
        return remoteTargetDao.find(remoteTargetId).getService().getUuid();
    }
}

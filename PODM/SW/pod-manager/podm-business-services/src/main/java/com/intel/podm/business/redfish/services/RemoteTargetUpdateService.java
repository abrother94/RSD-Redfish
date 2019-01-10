/*
 * Copyright (c) 2017 Intel Corporation
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

import com.intel.podm.actions.ActionException;
import com.intel.podm.actions.RemoteTargetUpdateInvoker;
import com.intel.podm.business.BusinessApiException;
import com.intel.podm.business.EntityOperationException;
import com.intel.podm.business.entities.redfish.RemoteTarget;
import com.intel.podm.business.redfish.EntityTreeTraverser;
import com.intel.podm.business.services.context.Context;
import com.intel.podm.common.types.actions.RemoteTargetUpdateDefinition;
import com.intel.podm.common.types.redfish.RedfishRemoteTarget;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.transaction.Transactional;

import static javax.transaction.Transactional.TxType.REQUIRES_NEW;

@RequestScoped
public class RemoteTargetUpdateService {

    @Inject
    private EntityTreeTraverser traverser;

    @Inject
    private RemoteTargetUpdateInvoker invoker;

    @Transactional(REQUIRES_NEW)
    public void updateRemoteTarget(Context context, RedfishRemoteTarget representation) throws BusinessApiException {
        RemoteTargetUpdateDefinition definition = new RemoteTargetUpdateDefinition(representation);

        RemoteTarget remoteTarget = (RemoteTarget) traverser.traverse(context);
        try {
            invoker.updateRemoteTarget(remoteTarget, definition);
        } catch (ActionException e) {
            throw new EntityOperationException(e.getMessage(), e);
        }
    }
}

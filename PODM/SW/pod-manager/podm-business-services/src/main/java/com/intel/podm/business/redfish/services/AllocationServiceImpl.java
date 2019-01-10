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

import com.intel.podm.allocation.AllocationRequestProcessingException;
import com.intel.podm.allocation.ComposedNodeStateChanger;
import com.intel.podm.allocation.CompositionException;
import com.intel.podm.allocation.NodeAllocator;
import com.intel.podm.assembly.tasks.NodeTasksCoordinator;
import com.intel.podm.business.EntityOperationException;
import com.intel.podm.business.RequestValidationException;
import com.intel.podm.business.redfish.services.helpers.ComposedNodeValidator;
import com.intel.podm.business.services.context.Context;
import com.intel.podm.business.services.redfish.AllocationService;
import com.intel.podm.business.services.redfish.requests.RequestedNode;
import com.intel.podm.common.enterprise.utils.retry.NumberOfRetriesOnRollback;
import com.intel.podm.common.enterprise.utils.retry.RetryOnRollbackInterceptor;
import com.intel.podm.common.types.Id;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.interceptor.Interceptors;
import javax.transaction.Transactional;

import static com.intel.podm.business.services.context.Context.contextOf;
import static com.intel.podm.business.services.context.ContextType.COMPOSED_NODE;
import static com.intel.podm.common.types.ComposedNodeState.ALLOCATED;
import static javax.transaction.Transactional.TxType.REQUIRES_NEW;

@RequestScoped
@Interceptors(RetryOnRollbackInterceptor.class)
@SuppressWarnings({"checkstyle:IllegalCatch", "checkstyle:ClassFanOutComplexity"})
public class AllocationServiceImpl implements AllocationService {
    @Inject
    private NodeAllocator nodeAllocator;

    @Inject
    private ComposedNodeValidator composedNodeValidator;

    @Inject
    private NodeTasksCoordinator nodeTasksCoordinator;

    @Inject
    private ComposedNodeStateChanger composedNodeStateChanger;

    @Override
    @NumberOfRetriesOnRollback(50)
    @Transactional(REQUIRES_NEW)
    public Context allocate(RequestedNode requestedNode) throws EntityOperationException, RequestValidationException {
        String baseExceptionMessage = "Creation failed due to allocation failure: ";
        Id composedNodeId;
        try {
            composedNodeValidator.validateExistenceOfIncludedResources(requestedNode);
            composedNodeId = nodeAllocator.compose(requestedNode).getId();
        } catch (AllocationRequestProcessingException e) {
            throw new RequestValidationException(baseExceptionMessage + e.getMessage(), e.getViolations(), e);
        } catch (CompositionException e) {
            throw new EntityOperationException(baseExceptionMessage + e.getMessage(), e);
        }

        try {
            nodeTasksCoordinator.setTasksForNode(composedNodeId, nodeAllocator.getAssemblyTasks());
        } catch (IllegalStateException e) {
            String msg = "Creation failed due to allocation failure: Composed Node [" + composedNodeId + "] has been already allocated.";
            throw new EntityOperationException(msg, e);
        }

        composedNodeStateChanger.change(composedNodeId, ALLOCATED);
        return contextOf(composedNodeId, COMPOSED_NODE);
    }
}

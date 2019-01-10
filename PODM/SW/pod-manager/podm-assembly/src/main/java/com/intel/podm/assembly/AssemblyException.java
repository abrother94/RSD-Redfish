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

package com.intel.podm.assembly;

import com.intel.podm.common.types.redfish.RedfishErrorResponse;
import com.intel.podm.common.types.redfish.RedfishErrorResponseCarryingException;

public class AssemblyException extends Exception implements RedfishErrorResponseCarryingException {
    private final RedfishErrorResponse errorResponse;

    public AssemblyException(String message, RedfishErrorResponse response, Throwable cause) {
        super(message, cause);
        this.errorResponse = response;
    }

    public AssemblyException(String message) {
        super(message);
        this.errorResponse = null;
    }

    public RedfishErrorResponse getErrorResponse() {
        return errorResponse;
    }
}

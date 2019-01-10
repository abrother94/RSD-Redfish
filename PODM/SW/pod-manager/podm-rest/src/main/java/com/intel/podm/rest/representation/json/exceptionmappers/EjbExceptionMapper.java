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

package com.intel.podm.rest.representation.json.exceptionmappers;

import com.intel.podm.common.logger.Logger;

import javax.ejb.EJBException;
import javax.inject.Inject;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;
import java.util.concurrent.RejectedExecutionException;

import static com.intel.podm.rest.error.PodmExceptions.internalServerError;
import static com.intel.podm.rest.error.PodmExceptions.serviceUnavailable;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

@Provider
@Produces(APPLICATION_JSON)
public class EjbExceptionMapper implements ExceptionMapper<EJBException> {
    @Inject
    private Logger logger;

    @Override
    public Response toResponse(EJBException exception) {
        logger.e("Application Error: " + exception.getMessage(), exception);
        if (exception.getCause() instanceof RejectedExecutionException) {
            return serviceUnavailable().getResponse();
        } else {
            return internalServerError().getResponse();
        }
    }
}

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
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.intel.podm.client.api.resources.redfish.SimpleStorageDeviceResource;
import com.intel.podm.common.types.Status;
import com.intel.podm.common.types.redfish.IgnoreAutomaticOem;

import java.math.BigDecimal;

import static com.intel.podm.client.resources.UnknownOemsHelper.convertJsonNodeToString;

public class SimpleStorageDeviceResourceImpl implements SimpleStorageDeviceResource {
    @JsonProperty("Name")
    private String name;

    @JsonProperty("Manufacturer")
    private String manufacturer;

    @JsonProperty("Model")
    private String model;

    @JsonProperty("Status")
    private Status status;

    @JsonProperty("CapacityBytes")
    private BigDecimal capacityBytes;

    @IgnoreAutomaticOem
    private String oem;

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getManufacturer() {
        return manufacturer;
    }

    @Override
    public String getModel() {
        return model;
    }

    @Override
    public Status getStatus() {
        return status;
    }

    @Override
    public BigDecimal getCapacityBytes() {
        return capacityBytes;
    }

    @Override
    public String getOem() {
        return oem;
    }

    @JsonProperty("Oem")
    public void setOem(JsonNode jsonNode) throws JsonProcessingException {
        oem = convertJsonNodeToString(jsonNode);
    }
}

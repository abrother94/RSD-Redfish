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

package com.intel.podm.redfish.json.templates.attributes;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.intel.podm.business.services.redfish.odataid.ODataId;

@JsonPropertyOrder({"@odata.id", "regionId"})
public class InterleaveSetJson {
    @JsonUnwrapped
    @JsonProperty("@odata.id")
    private ODataId oDataId;
    @JsonProperty("RegionId")
    private String regionId;

    public InterleaveSetJson(ODataId oDataId, String regionId) {
        this.oDataId = oDataId;
        this.regionId = regionId;
    }
}

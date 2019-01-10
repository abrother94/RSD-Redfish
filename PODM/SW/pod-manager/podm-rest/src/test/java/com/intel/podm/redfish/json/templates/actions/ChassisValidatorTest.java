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

package com.intel.podm.redfish.json.templates.actions;

import com.intel.podm.common.types.redfish.RedfishChassis;
import com.intel.podm.redfish.json.templates.actions.constraints.ChassisConstraint.ChassisConstraintValidator;
import org.testng.annotations.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

@SuppressWarnings({"checkstyle:MethodName"})
public class ChassisValidatorTest {
    @Test
    public void whenEmptyJsonProvided_shouldReturnFalse() throws Exception {
        ChassisConstraintValidator chassisConstraintValidator = new ChassisConstraintValidator();

        RedfishChassis json = mock(RedfishChassis.class);

        assertFalse(chassisConstraintValidator.isValid(json, null));
    }

    @Test
    public void whenJsonWithAssetTagProvided_shouldReturnTrue() throws Exception {
        ChassisConstraintValidator chassisConstraintValidator = new ChassisConstraintValidator();

        RedfishChassis json = prepareRedfishChassisWithAssetTag("DUMMY_DATA");

        assertTrue(chassisConstraintValidator.isValid(json, null));
    }

    @Test
    public void whenJsonWithEmptyAssetTag_shouldReturnFalse() throws Exception {
        ChassisConstraintValidator computerSystemConstraintValidator = new ChassisConstraintValidator();

        RedfishChassis json = prepareRedfishChassisWithAssetTag(null);

        assertFalse(computerSystemConstraintValidator.isValid(json, null));
    }

    private RedfishChassis prepareRedfishChassisWithAssetTag(String assetTag) {
        RedfishChassis json = mock(RedfishChassis.class);

        when(json.getAssetTag()).thenReturn(assetTag);

        return json;
    }
}

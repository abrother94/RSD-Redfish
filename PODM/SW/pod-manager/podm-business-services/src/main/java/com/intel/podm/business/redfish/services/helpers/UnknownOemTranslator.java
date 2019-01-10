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

package com.intel.podm.business.redfish.services.helpers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.intel.podm.business.dto.redfish.attributes.UnknownOemDto;
import com.intel.podm.business.entities.dao.DiscoverableEntityDao;
import com.intel.podm.business.entities.redfish.ExternalService;
import com.intel.podm.business.entities.redfish.base.DiscoverableEntity;
import com.intel.podm.business.entities.redfish.embeddables.UnknownOem;
import com.intel.podm.business.services.context.Context;
import com.intel.podm.common.logger.Logger;

import javax.inject.Inject;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.intel.podm.business.redfish.Contexts.toContext;
import static java.net.URI.create;
import static java.util.stream.Collectors.toList;

public class UnknownOemTranslator {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String ODATA_ID = "@odata.id";

    @Inject
    private Logger logger;

    @Inject
    private DiscoverableEntityDao discoverableEntityDao;

    public List<UnknownOemDto> translateUnknownOemToDtos(ExternalService externalService, Collection<UnknownOem> unknownOems) {
        return unknownOems.stream()
            .map(unknownOem -> buildUnknownOemDto(externalService, unknownOem))
            .collect(toList());
    }

    public UnknownOemDto translateStringOemToDto(ExternalService externalService, String oem) {
        ObjectNode objectNode = convertStringToObjectNode(oem);
        Map<String, Context> foundContexts = getExistingContexts(externalService, objectNode);

        return UnknownOemDto.newBuilder()
            .oemValue(objectNode)
            .foundContexts(foundContexts)
            .build();
    }

    private UnknownOemDto buildUnknownOemDto(ExternalService externalService, UnknownOem unknownOem) {
        ObjectNode objectNode = convertStringToObjectNode(unknownOem.getOemValue());
        Map<String, Context> foundContexts = getExistingContexts(externalService, objectNode);

        return UnknownOemDto.newBuilder()
            .oemPath(unknownOem.getOemPath())
            .oemValue(objectNode)
            .foundContexts(foundContexts)
            .build();
    }

    private ObjectNode convertStringToObjectNode(String value) {
        if (value != null) {
            try {
                return (ObjectNode) OBJECT_MAPPER.readTree(value);
            } catch (IOException | ClassCastException e) {
                logger.e("Couldn't convert: [" + value + "] to ObjectNode", e);
            }
        }

        return OBJECT_MAPPER.createObjectNode();
    }

    private Map<String, Context> getExistingContexts(ExternalService externalService, JsonNode jsonNode) {
        Map<String, Context> foundContexts = new HashMap<>();
        JsonNode oDataIdJsonNode = jsonNode.get(ODATA_ID);
        if (oDataIdJsonNode != null && oDataIdJsonNode.isTextual()) {
            String sourceUriString = oDataIdJsonNode.asText();
            List<DiscoverableEntity> discoverableEntities = discoverableEntityDao.getByExternalServiceAndSourceUri(externalService, create(sourceUriString));

            if (discoverableEntities.size() == 1) {
                Context context = toContext(discoverableEntities.iterator().next());
                foundContexts.put(sourceUriString, context);
            }
        }

        for (JsonNode childNode : jsonNode) {
            foundContexts.putAll(getExistingContexts(externalService, childNode));
        }

        return foundContexts;
    }
}

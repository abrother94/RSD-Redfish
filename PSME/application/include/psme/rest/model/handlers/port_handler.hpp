/*!
 * @copyright
 * Copyright (c) 2015-2017 Intel Corporation
 *
 * @copyright
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * @copyright
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * @copyright
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @file port_handler.hpp
 *
 * Specialization of GenericHandler for Ports
 * */

#pragma once



#include "agent-framework/module/requests/pnc/get_port_info.hpp"
#include "agent-framework/module/pnc_components.hpp"



namespace psme {
namespace rest {
namespace model {
namespace handler {

using PortHandlerBase = GenericHandler <
agent_framework::model::requests::GetPortInfo,
agent_framework::model::Port,
IdPolicy<agent_framework::model::enums::Component::Port, NumberingZone::PARENT_SPACE>>;

/*!
 * @brief PortHandler template specialization.
 *
 * This is necessary because we have to handle PciePorts assigned to PcieZones in
 * the way that is inconsistent with most other components.
 * */
class PortHandler : public PortHandlerBase {
public:
    PortHandler() : PortHandlerBase() {}


    virtual ~PortHandler();


protected:
    using PncComponents = agent_framework::module::PncComponents;

    /*!
     * @brief collection might be strong or weak
     *
     * @param[in] parent_component Component of parent node
     */
    bool is_strong_collection(const Component parent_component) {
        return (Component::Switch == parent_component);
    }


    /*!
     * @brief Specialization of fetch_siblings()
     *
     * An PciePort can be either a subcomponent of a Switch or an Endpoint.
     * This code handles both cases.
     *
     * @param[in] ctx keeps data that is required during processing and
     *                needs to be passed down to sub-handlers
     * @param[in] parent_uuid uuid of parent whose subcomponents we want to
     *                        retrieve
     * @param[in] collection_name name of collection of elements to fetch
     */
    void fetch_siblings(Context& ctx, const std::string& parent_uuid,
                        const std::string& collection_name) override {
        if (is_strong_collection(ctx.get_parent_component())) {
            return PortHandlerBase::fetch_siblings(ctx, parent_uuid, collection_name);
        }
        else if (Component::Endpoint == ctx.get_parent_component()) {
            fetch_parent_children(ctx, parent_uuid, collection_name,
                                  PncComponents::get_instance()->get_endpoint_port_manager());
        }
        else {
            log_debug(GET_LOGGER("rest"), ctx.indent
                << "[" << static_cast<char>(ctx.mode) << "] "
                << "Found a Port under an unexpected parent " << parent_uuid);
        }
    }


    /*!
     * @brief  Specialization of remove_agent_data()
     *
     * This override is necessary to properly clean the Endpoint <-> Port
     * bindings for all the Ports.
     *
     * @param[in] gami_id uuid of the agent whose data is to be removed.
     * */
    void remove_agent_data(const std::string& gami_id) override {
        PncComponents::get_instance()->
            get_endpoint_port_manager().clean_resources_for_agent(gami_id);
        PortHandlerBase::remove_agent_data(gami_id);
    }


    /*!
     * @brief  Specialization of remove() from GenericManager.
     *
     * This override is necessary for clearing the PcieZone <-> PciePort bindings.
     *
     * @param[in] uuid uuid of the port to be removed.
     * */
    void remove(const std::string& uuid) override {
        // port is the child in Endpoint <-> Port relation
        PncComponents::get_instance()->
            get_endpoint_port_manager().remove_child(uuid);
        PortHandlerBase::remove(uuid);
    }


    bool do_accept_recursively(ResourceVisitor& visitor,
                               const std::string& parent_uuid,
                               const Component parent_component) override {
        if (is_strong_collection(parent_component)) {
            return PortHandlerBase::do_accept_recursively(visitor, parent_uuid, parent_component);
        }
        else {
            auto& manager = PncComponents::get_instance()->get_endpoint_port_manager();
            auto children = manager.get_children(parent_uuid);
            for (const std::string& child_uuid : children) {
                if (!do_accept(visitor, child_uuid)) {
                    return false; // break
                }
            }
        }
        return true;
    }
};


PortHandler::~PortHandler() {}

}
}
}
}


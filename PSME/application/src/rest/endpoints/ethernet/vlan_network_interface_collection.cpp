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
 * */

#include "agent-framework/module/requests/network/add_port_vlan.hpp"
#include "agent-framework/module/responses/network/add_port_vlan.hpp"
#include "configuration/configuration.hpp"
#include "psme/core/agent/agent_manager.hpp"
#include "psme/rest/constants/constants.hpp"
#include "psme/rest/endpoints/ethernet/vlan_network_interface_collection.hpp"
#include "psme/rest/model/handlers/handler_manager.hpp"
#include "psme/rest/model/handlers/generic_handler_deps.hpp"
#include "psme/rest/model/handlers/generic_handler.hpp"
#include "psme/rest/server/error/error_factory.hpp"
#include "psme/rest/validators/json_validator.hpp"
#include "psme/rest/validators/schemas/vlan_network_interface_collection.hpp"

using namespace psme::rest;
using namespace psme::rest::constants;
using namespace psme::rest::validators;
using namespace psme::rest::endpoint;



namespace {
json::Value make_prototype() {
    json::Value r(json::Value::Type::OBJECT);

    r[Common::ODATA_CONTEXT] ="/redfish/v1/$metadata#VLanNetworkInterfaceCollection.VLanNetworkInterfaceCollection";
    r[Common::ODATA_ID] = json::Value::Type::NIL;
    r[Common::ODATA_TYPE] = "#VLanNetworkInterfaceCollection.VLanNetworkInterfaceCollection";
    r[Common::NAME] = "VLAN Network Interface Collection";
    r[Common::DESCRIPTION] = "Collection of VLAN Network Interfaces";
    r[Collection::ODATA_COUNT] = json::Value::Type::NIL;
    r[Collection::MEMBERS] = json::Value::Type::ARRAY;
    return r;
}

const json::Value validate_post_request(const server::Request& request) {
    return JsonValidator::validate_request_body(request,
                                                schema::VlanNetworkInterfaceCollectionPostSchema::get_procedure());
}

}

VlanNetworkInterfaceCollection::VlanNetworkInterfaceCollection(const std::string& path) : EndpointBase(path) {}
VlanNetworkInterfaceCollection::~VlanNetworkInterfaceCollection() {}

void VlanNetworkInterfaceCollection::get(const server::Request& req, server::Response& res) {
    auto r = ::make_prototype();

    r[Common::ODATA_ID] = PathBuilder(req).build();
#if 0
    auto port_uuid =
        psme::rest::model::Find<agent_framework::model::EthernetSwitchPort>
        (req.params[PathParam::SWITCH_PORT_ID]).via<agent_framework::model::EthernetSwitch>
        (req.params[PathParam::ETHERNET_SWITCH_ID]).get_uuid();

    auto keys = agent_framework::module::NetworkComponents::get_instance()->
                        get_port_vlan_manager().get_ids(port_uuid);

    r[Collection::ODATA_COUNT] = static_cast<std::uint32_t>(keys.size());

    for (const auto& key : keys) {
        json::Value link_elem(json::Value::Type::OBJECT);
        link_elem[Common::ODATA_ID] = PathBuilder(req).append(key).build();
        r[Collection::MEMBERS].push_back(std::move(link_elem));
    }
#else
    char resultA[256] = {0};	
    char command[256] = {0};
    int iPort = std::stoi(req.params[PathParam::SWITCH_PORT_ID]);

    sprintf(command, "vlan.sh get vlan_port_count %d" , iPort);
    memset(resultA,0x0, sizeof(resultA));
    exec_shell(command, resultA);

    if(strlen(resultA) != 0)
    {
        int icount = std::stoi(resultA);
        int i =0;
        r[Collection::ODATA_COUNT] = static_cast<std::uint32_t>(icount);

	 for (i = 0; i < icount ; i++) {
            json::Value link_elem(json::Value::Type::OBJECT);
    
            sprintf(command, "vlan.sh get vlan_port_value %d", i);
            memset(resultA,0x0, sizeof(resultA));
            exec_shell(command, resultA);
    
           if(strlen(resultA) != 0)
           {
               link_elem[Common::ODATA_ID] = PathBuilder(req).append(atoi(resultA)).build();
               r[Collection::MEMBERS].push_back(std::move(link_elem));
           }
        }	
    }
    else
        r[Collection::ODATA_COUNT] = 0;

#endif
    set_response(res, r);
}

void VlanNetworkInterfaceCollection::post(const server::Request& req, server::Response& res) {
    auto port = psme::rest::model::Find<agent_framework::model::EthernetSwitchPort>(req.params[PathParam::SWITCH_PORT_ID])
        .via<agent_framework::model::EthernetSwitch>(req.params[PathParam::ETHERNET_SWITCH_ID])
        .get();

    std::string agent_id = port.get_agent_id();
    std::string port_id = port.get_uuid();

    const auto json = validate_post_request(req);

    auto vlan_id = json[Vlan::VLAN_ID].as_uint();
    bool tagged = json[Common::OEM][Common::RACKSCALE][Vlan::TAGGED].as_bool();
    bool en          = json[Vlan::VLAN_ENABLE].as_bool();

#if 0
    auto oem = agent_framework::model::attribute::Oem{};

    agent_framework::model::requests::AddPortVlan add_port_vlan_req{
        port.get_uuid(),
        json.is_member(Common::NAME) ? json[Common::NAME].as_string() : Json::Value::null,
        vlan_id,
        tagged,
        oem
    };

    const auto& gami_agent = psme::core::agent::AgentManager::get_instance()->get_agent(agent_id);

    auto add_vlan = [&, gami_agent] {
        auto response = gami_agent->execute<agent_framework::model::responses::AddPortVlan>(add_port_vlan_req);

        psme::rest::model::handler::HandlerManager::get_instance()->get_handler(
            agent_framework::model::enums::Component::EthernetSwitchPortVlan)->load(
            gami_agent, port_id,
            agent_framework::model::enums::Component::EthernetSwitchPort, response.get_port_vlan());

        auto created_vlan = agent_framework::module::NetworkComponents::get_instance()->
            get_port_vlan_manager().get_entry(response.get_port_vlan());

        psme::rest::endpoint::utils::set_location_header(
            res, PathBuilder(req).append(created_vlan.get_id()).build());

        res.set_status(server::status_2XX::CREATED);
    };
    gami_agent->execute_in_transaction(add_vlan);
#else

    char resultA[256] = {0};	
    char command[256] = {0};
    int iPort = std::stoi(req.params[PathParam::SWITCH_PORT_ID]);

    sprintf(command, "vlan.sh set vlan_port_value %d %d %d %d " ,vlan_id,  iPort, !tagged, en);
    memset(resultA,0x0, sizeof(resultA));
    exec_shell(command, resultA);

    psme::rest::endpoint::utils::set_location_header(res, PathBuilder(req).append(vlan_id).build());

    res.set_status(server::status_2XX::CREATED);
#endif

}
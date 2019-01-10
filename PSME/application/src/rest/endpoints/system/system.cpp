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

#include "agent-framework/module/requests/common.hpp"
#include "agent-framework/module/responses/common.hpp"
#include "agent-framework/module/constants/compute.hpp"

#include "psme/rest/utils/status_helpers.hpp"
#include "psme/rest/validators/json_validator.hpp"
#include "psme/rest/validators/schemas/system.hpp"
#include "psme/rest/endpoints/system/system.hpp"
#include "psme/rest/server/error/error_factory.hpp"
#include "psme/rest/model/handlers/generic_handler.hpp"

#include "agent-framework/service_uuid.hpp"
/* Do not remove numeric header - needed by ARM compilation */
#include <numeric>



using namespace psme::rest;
using namespace psme::rest::constants;
using namespace psme::rest::endpoint::utils;
using namespace psme::rest::validators;
using agent_framework::generic::ServiceUuid;
using BootOverrideTarget = agent_framework::model::enums::BootOverrideTarget;
using BootOverrideSupported = agent_framework::model::System::BootOverrideSupported;

namespace {
json::Value make_prototype() {
    json::Value response(json::Value::Type::OBJECT);

    response[Common::ODATA_CONTEXT] = "/redfish/v1/$metadata#ComputerSystem.ComputerSystem";
    response[Common::ODATA_ID] = json::Value::Type::NIL;
    response[Common::ODATA_TYPE] = "#ComputerSystem.v1_3_0.ComputerSystem";
    response[Common::ID] = json::Value::Type::NIL;
    response[Common::NAME] = "Computer System";
    response[Common::DESCRIPTION] = "Computer System description";
    response[System::SYSTEM_TYPE] = json::Value::Type::NIL;
    response[Common::ASSET_TAG] = json::Value::Type::NIL;
    response[Common::MANUFACTURER] = json::Value::Type::NIL;
    response[Common::MODEL] = json::Value::Type::NIL;
    response[System::SKU] = json::Value::Type::NIL;
    response[Common::SERIAL] = json::Value::Type::NIL;
    response[Common::PART_NUMBER] = json::Value::Type::NIL;
    response[Common::UUID] = json::Value::Type::NIL;
    response[System::HOST_NAME] = json::Value::Type::NIL;
    response[Common::STATUS][Common::STATE] = json::Value::Type::NIL;
    response[Common::STATUS][Common::HEALTH] = json::Value::Type::NIL;
    response[Common::STATUS][Common::HEALTH_ROLLUP] = json::Value::Type::NIL;
    response[System::INDICATOR_LED] = json::Value::Type::NIL;
    response[System::POWER_STATE] = json::Value::Type::NIL;
    response[System::BIOS_VERSION] = json::Value::Type::NIL;

    json::Value boot;
    boot[System::BOOT_SOURCE_OVERRIDE_ENABLED] = json::Value::Type::NIL;
    boot[System::BOOT_SOURCE_OVERRIDE_TARGET] = json::Value::Type::NIL;

    response[System::BOOT] = std::move(boot);

    json::Value processors;
    processors[System::COUNT] = json::Value::Type::NIL;
    processors[Common::MODEL] = json::Value::Type::NIL;
    processors[Common::STATUS][Common::STATE] = json::Value::Type::NIL;
    processors[Common::STATUS][Common::HEALTH] = json::Value::Type::NIL;
    processors[Common::STATUS][Common::HEALTH_ROLLUP] = json::Value::Type::NIL;
    response[System::PROCESSOR_SUMMARY] = std::move(processors);

    json::Value memory;
    memory[System::TOTAL_SYSTEM_MEMORY_GIB] = json::Value::Type::NIL;
    memory[Common::STATUS][Common::STATE] = json::Value::Type::NIL;
    memory[Common::STATUS][Common::HEALTH] = json::Value::Type::NIL;
    memory[Common::STATUS][Common::HEALTH_ROLLUP] = json::Value::Type::NIL;
    response[System::MEMORY_SUMMARY] = std::move(memory);

    response[System::PROCESSORS] = json::Value::Type::NIL;
#ifndef COCP		
    response[System::ETHERNET_INTERFACES] = json::Value::Type::NIL;
#endif 

#ifdef CSYSTEM_NETWORK		
    response[System::NETWORK_INTERFACES] = json::Value::Type::NIL;
#endif
    response[System::STORAGE] = json::Value::Type::NIL;
    response[System::MEMORY] = json::Value::Type::NIL;
    response[Chassis::PCIE_DEVICES] = json::Value::Type::ARRAY;
    response[PcieDevice::PCIE_FUNCTIONS] = json::Value::Type::ARRAY;

    response[Common::LINKS][Common::ODATA_TYPE] = "#ComputerSystem.v1_2_0.Links";
    response[Common::LINKS][Common::CHASSIS] = json::Value::Type::ARRAY;
    response[Common::LINKS][System::ENDPOINTS] = json::Value::Type::ARRAY;
    response[Common::LINKS][Common::MANAGED_BY] = json::Value::Type::ARRAY;
    response[Common::LINKS][Common::OEM] = json::Value::Type::OBJECT;

    json::Value allowable;
//  allowable.push_back(System::ON);
    allowable.push_back(System::FORCE_OFF);
    allowable.push_back(System::GRACEFUL_SHUTDOWN);
    allowable.push_back(System::GRACEFUL_RESTART);
    allowable.push_back(System::FORCE_RESTART);

    json::Value actions;
    std::string hash_computer_system_reset(constants::Common::HASH);
    hash_computer_system_reset.append(constants::System::COMPUTER_SYSTEM_RESET);
    actions[hash_computer_system_reset][System::TARGET] = json::Value::Type::NIL;
    actions[hash_computer_system_reset][System::ALLOWABLE_RESET_TYPES] = std::move(allowable);
    response[Common::ACTIONS] = std::move(actions);

    json::Value rs;

    rs[Common::ODATA_TYPE] = "#Intel.Oem.ComputerSystem";
    rs[System::PCI_DEVICES] = json::Value::Type::ARRAY;
    rs[System::PCIE_CONNECTION_ID] = json::Value::Type::ARRAY;
    rs[System::PROCESSOR_SOCKETS] = json::Value::Type::NIL;
    rs[System::MEMORY_SOCKETS] = json::Value::Type::NIL;
    rs[System::DISCOVERY_STATE] = json::Value::Type::NIL;
    response[Common::OEM][Common::RACKSCALE] = std::move(rs);

    return response;
}


void add_processors_summary(const agent_framework::model::System& system, json::Value& response) {
    const agent_framework::model::enums::State ENABLED = agent_framework::model::enums::State::Enabled;

    // PROCESSORS SUMMARY
    auto procs = agent_framework::module::get_manager<agent_framework::model::Processor>()
        .get_keys(system.get_uuid());

    response[constants::System::PROCESSOR_SUMMARY][Common::MODEL] = json::Value::Type::NIL;
    auto processors_count = static_cast<std::uint32_t>(procs.size());
    if (processors_count > 0) {
        const auto& proc = agent_framework::module::get_manager<agent_framework::model::Processor>()
            .get_entry(procs.front());
        response[constants::System::PROCESSOR_SUMMARY][Common::MODEL] = proc.get_model_name();
    }

    response[constants::System::PROCESSOR_SUMMARY][Common::STATUS][Common::STATE] = ENABLED.to_string();
    auto summarized_proc_health = psme::rest::endpoint::HealthRollup<agent_framework::model::System>()
        .get(system.get_uuid(), agent_framework::model::enums::Component::Processor);

    response[Common::OEM][Common::RACKSCALE][System::PROCESSOR_SOCKETS] = processors_count;
    response[constants::System::PROCESSOR_SUMMARY][Common::STATUS][Common::HEALTH] = summarized_proc_health;
    response[constants::System::PROCESSOR_SUMMARY][Common::STATUS][Common::HEALTH_ROLLUP] = summarized_proc_health;

    auto is_processor_present = [](const agent_framework::model::Processor& p) {
        return (p.get_status().get_state() == agent_framework::model::enums::State::Absent) ? 0 : 1;
    };
    auto available_processors = psme::rest::endpoint::utils::query_entries
        <agent_framework::model::Processor, std::uint32_t>(system.get_uuid(), is_processor_present);
    response[constants::System::PROCESSOR_SUMMARY][constants::System::COUNT] =
        std::accumulate(available_processors.begin(), available_processors.end(), 0);
}


void add_memory_summary(const agent_framework::model::System& system, json::Value& response) {
    const agent_framework::model::enums::State ENABLED = agent_framework::model::enums::State::Enabled;

    auto memory_modules = agent_framework::module::get_manager<agent_framework::model::Memory>()
        .get_keys(system.get_uuid());

    OptionalField<std::uint32_t> total_size_mb{};
    auto get_memory_size = [](const agent_framework::model::Memory& m) { return m.get_capacity_mb(); };
    auto memory_sizes = psme::rest::endpoint::utils::query_entries
        <agent_framework::model::Memory, OptionalField<std::uint32_t>>(system.get_uuid(), get_memory_size);

    for (const auto& mem_size: memory_sizes) {
        total_size_mb = total_size_mb + mem_size;
    }

    response[constants::System::MEMORY_SUMMARY][constants::System::TOTAL_SYSTEM_MEMORY_GIB] =
        (total_size_mb.has_value() ?
         json::Value(endpoint::utils::round(endpoint::utils::mb_to_gib(total_size_mb), 2)) :
         json::Value(json::Value::Type::NIL));

    response[constants::System::MEMORY_SUMMARY][Common::STATUS][Common::STATE] = ENABLED.to_string();
    auto summarized_memory_health = psme::rest::endpoint::HealthRollup<agent_framework::model::System>()
        .get(system.get_uuid(), agent_framework::model::enums::Component::Memory);

    response[constants::System::MEMORY_SUMMARY][Common::STATUS][Common::HEALTH] = summarized_memory_health;
    response[constants::System::MEMORY_SUMMARY][Common::STATUS][Common::HEALTH_ROLLUP] = summarized_memory_health;

    response[Common::OEM][Common::RACKSCALE][System::MEMORY_SOCKETS] = memory_modules.size();
}


void add_system_relations(const agent_framework::model::System& system, json::Value& response) {
    // PCI DEVICES
    for (const auto& pci: system.get_pci_devices()) {
        json::Value pci_device;
        pci_device[Common::VENDOR_ID] = pci.get_vendor_id();
        pci_device[Common::DEVICE_ID] = pci.get_device_id();
        response[Common::OEM][Common::RACKSCALE][System::PCI_DEVICES].push_back(std::move(pci_device));
    }

    // CABLE IDS/PCIE CONNECTIONS
    for (const auto& cable_id: system.get_cable_ids()) {
        response[Common::OEM][Common::RACKSCALE][System::PCIE_CONNECTION_ID].push_back(cable_id);
    }

    // PCIe Devices
    // the manager for this system is also the manager for all the pcie devices
    const auto& manager_uuid = system.get_parent_uuid();
    for (const auto& device_uuid : agent_framework::module::get_manager<agent_framework::model::PcieDevice>().get_keys(
        manager_uuid)) {
        json::Value device_link;
        device_link[Common::ODATA_ID] = endpoint::utils::get_component_url(
            agent_framework::model::enums::Component::PcieDevice, device_uuid);
        response[Chassis::PCIE_DEVICES].push_back(std::move(device_link));
    }

    // PCIe Functions
    // Per the architect's decision, we do not fill the PCIeFunctions array

    // Endpoints
    // Per the architect's decision, we do not fill the Endpoints array

    // the manager for this system should have one Fabric, which is the parent for all the Endpoints
    const auto fabric_uuids = agent_framework::module::get_manager<agent_framework::model::Fabric>().get_keys(
        manager_uuid);
}


void make_children_links(const server::Request& req, json::Value& response) {
    using psme::rest::endpoint::PathBuilder;
    response[constants::System::PROCESSORS][Common::ODATA_ID] =
        PathBuilder(req).append(constants::System::PROCESSORS).build();

#ifndef COCP		
    response[constants::System::ETHERNET_INTERFACES][Common::ODATA_ID] =
        PathBuilder(req).append(constants::System::ETHERNET_INTERFACES).build();
#endif

	response[constants::System::STORAGE][Common::ODATA_ID] =
        PathBuilder(req).append(constants::System::STORAGE).build();
    response[constants::System::MEMORY][Common::ODATA_ID] =
        PathBuilder(req).append(constants::System::MEMORY).build();

#ifdef CSYSTEM_NETWORK	
	response[constants::System::NETWORK_INTERFACES][Common::ODATA_ID] =
        PathBuilder(req).append(constants::System::NETWORK_INTERFACES).build();
#endif

}


static const std::map<std::string, std::string> gami_to_rest_attributes = {
    {agent_framework::model::literals::System::BOOT_OVERRIDE,
        endpoint::PathBuilder(constants::System::BOOT)
            .append(constants::System::BOOT_SOURCE_OVERRIDE_ENABLED).build()},
    {agent_framework::model::literals::System::BOOT_OVERRIDE_MODE,
        endpoint::PathBuilder(constants::System::BOOT)
            .append(constants::System::BOOT_SOURCE_OVERRIDE_ENABLED).build()},
    {agent_framework::model::literals::System::BOOT_OVERRIDE_TARGET,
        endpoint::PathBuilder(constants::System::BOOT)
            .append(constants::System::BOOT_SOURCE_OVERRIDE_TARGET).build()},
    {agent_framework::model::literals::System::ASSET_TAG,
        constants::Common::ASSET_TAG}
};


void make_parent_links(const agent_framework::model::System& system, json::Value& response) {
    // find manager of this system
    try {
        json::Value managed_by;
        managed_by[Common::ODATA_ID] = psme::rest::endpoint::utils::get_component_url(
            agent_framework::model::enums::Component::Manager, system.get_parent_uuid());
        response[Common::LINKS][Common::MANAGED_BY].push_back(managed_by);
	
    }
    catch (const agent_framework::exceptions::InvalidUuid&) {}

    // find chassis containing this system
    try {
        json::Value chassis;
        chassis[Common::ODATA_ID] =
            psme::rest::endpoint::utils::get_component_url(agent_framework::model::enums::Component::Chassis,
                                                           system.get_chassis());
        response[Common::LINKS][constants::Common::CHASSIS].push_back(chassis);
    }
    catch (const agent_framework::exceptions::InvalidUuid&) {}
}

#if 0
void reload_network_device_function(psme::core::agent::JsonAgentSPtr gami_agent, const std::string& system_uuid) {
    const auto network_device_uuids =
        agent_framework::module::get_manager<agent_framework::model::NetworkDevice>().get_keys(system_uuid);
    if (network_device_uuids.empty() || network_device_uuids.size() > 1) {
        log_error(GET_LOGGER("rest"), "Invalid number of Network Devices for System: '" + system_uuid + "'!");
        return;
    }
    const auto network_function_uuids = agent_framework::module::get_manager<
        agent_framework::model::NetworkDeviceFunction>().get_keys(network_device_uuids.front());
    if (network_function_uuids.empty() || network_function_uuids.size() > 1) {
        log_error(GET_LOGGER("rest"),
                  "Invalid number of Network Device Functions for Device: '" + network_device_uuids.front() + "'!");
        return;
    }

    psme::rest::model::handler::HandlerManager::get_instance()->get_handler(
        agent_framework::model::enums::Component::NetworkDeviceFunction)->
        load(gami_agent,
             network_device_uuids.front(),
             agent_framework::model::enums::Component::NetworkDevice,
             network_function_uuids.front(),
             false);
}
#endif
}


endpoint::System::System(const std::string& path) : EndpointBase(path) {}


endpoint::System::~System() {}


void endpoint::System::get(const server::Request& req, server::Response& res) {
    auto response = make_prototype();
    response[Common::ODATA_ID] = PathBuilder(req).build();

    auto system = psme::rest::model::Find<agent_framework::model::System>(req.params[PathParam::SYSTEM_ID]).get();
    make_parent_links(system, response);

    response[constants::Common::ODATA_ID] = PathBuilder(req).build();
    response[constants::Common::ID] = req.params[PathParam::SYSTEM_ID];
    response[constants::System::SYSTEM_TYPE] = system.get_system_type();
    response[Common::MANUFACTURER] = system.get_fru_info().get_manufacturer();
    response[Common::MODEL] = system.get_fru_info().get_model_number();
    response[Common::SERIAL] = system.get_fru_info().get_serial_number();
    response[Common::PART_NUMBER] = system.get_fru_info().get_part_number();
	response[constants::Common::UUID] = ServiceUuid::get_instance()->get_service_uuid();
    endpoint::status_to_json(system, response);
    response[Common::STATUS][Common::HEALTH_ROLLUP] =
        endpoint::HealthRollup<agent_framework::model::System>().get(system.get_uuid());
    response[constants::System::POWER_STATE] = system.get_power_state().to_string();

	{
		char command[256] = {0};
		char resultA[256] = {0};
		sprintf(command, "%s" ,"dmidecode | grep 'BIOS Revision' | awk '{print $3}'");
		memset(resultA,0x0, sizeof(resultA));
		exec_shell(command, resultA);

		if(strlen(resultA) != 0)
		{
			resultA[strcspn(resultA, "\r\n")]=0;
			response[constants::System::BIOS_VERSION] = resultA;
		}


	}
#if 0
#ifdef COMCAST
{
// CPU UTIL INFO //
    char command[256] = {0};
    char resultA[256] = {0};
    sprintf(command, "%s" ,"collect_cpu_util_info.sh COUNT");
    memset(resultA,0x0, sizeof(resultA));
    exec_shell(command, resultA);
    int count = 0;	
	
    if(strlen(resultA) != 0)
    {
        count = atoi(resultA);
        json::Value jsoncpu; 
        for (int i = 1; i <= count; i++) 
        {
            sprintf(command, "%s %d" ,"collect_cpu_util_info.sh INDEX", i);
            memset(resultA,0x0, sizeof(resultA));
            exec_shell(command, resultA);

            if(strlen(resultA) != 0)
            {		
                char tmp1[5][128];
                sscanf(resultA, "%s %s %s %s %s" ,  tmp1[0] , tmp1[1],  tmp1[2], tmp1[3], tmp1[4]);
                jsoncpu["CPU UTIL"]["ID"]          = i;	
                jsoncpu["CPU UTIL"]["PID"]        =  tmp1[0];	
                jsoncpu["CPU UTIL"]["CPU usage %"]    =  tmp1[1];	
                jsoncpu["CPU UTIL"]["Username"]      =  tmp1[2];	
                jsoncpu["CPU UTIL"]["Task Name"]      = tmp1[3];	
                jsoncpu["CPU UTIL"]["Task Param"]    = tmp1[4];	
                response["CPU USAGE INFO"].push_back(std::move(jsoncpu));	
            }

        }
    }

// MEM UTIL INFO //

    sprintf(command, "%s" ,"collect_mem_util_info.sh COUNT");
    memset(resultA,0x0, sizeof(resultA));
    exec_shell(command, resultA);
	
    if(strlen(resultA) != 0)
    {
        count = atoi(resultA);
        json::Value jsonmem; 
        for (int i = 1; i <= count; i++) 
        {
            sprintf(command, "%s %d" ,"collect_mem_util_info.sh INDEX", i);
            memset(resultA,0x0, sizeof(resultA));
            exec_shell(command, resultA);

            if(strlen(resultA) != 0)
            {		
                char tmp1[6][128];
                sscanf(resultA, "%s %s %s %s %s %s" ,  tmp1[0] , tmp1[1],  tmp1[2], tmp1[3], tmp1[4], tmp1[5]);
                jsonmem["MEM UTIL"]["ID"]          = i;	
                jsonmem["MEM UTIL"]["PID"]        =  tmp1[0];	
                jsonmem["MEM UTIL"]["Memory usage %"]    =  tmp1[1];	
                jsonmem["MEM UTIL"]["Virtual Memory Size"]      =  tmp1[2];	
                jsonmem["MEM UTIL"]["Resident Set Size"]      =  tmp1[3];	
                jsonmem["MEM UTIL"]["Name"]      = tmp1[4];	
                jsonmem["MEM UTIL"]["Param"]    = tmp1[5];	
                response["MEM USAGE INFO"].push_back(std::move(jsonmem));	
            }

        }
    }

    sprintf(command, "%s" ,"collect_mem_util_info.sh FREE");
    memset(resultA,0x0, sizeof(resultA));
    exec_shell(command, resultA);
	
    if(strlen(resultA) != 0)
    {
    //#total       used       free     shared    buffers     cached
        char tmp1[7][128];
        json::Value jsonmem; 	
        sscanf(resultA, "%s %s %s %s %s %s %s" ,  tmp1[0] , tmp1[1],  tmp1[2], tmp1[3], tmp1[4], tmp1[5], tmp1[6]);
        jsonmem["MEM UTIL"]["Total Memory"]        = tmp1[1];	
        jsonmem["MEM UTIL"]["Used Memory"]        = tmp1[2];	
        jsonmem["MEM UTIL"]["Free Memory"]         = tmp1[3];	
        jsonmem["MEM UTIL"]["Shared Memory"]     = tmp1[4];	
        jsonmem["MEM UTIL"]["Buffers Memory"]     = tmp1[5];	
        jsonmem["MEM UTIL"]["cached Memory"]     = tmp1[6];	
        response["MEM USAGE INFO"].push_back(std::move(jsonmem));		
    }

// DISK UTIL INFO //

    sprintf(command, "%s" ,"collect_disk_util_info.sh COUNT");
    memset(resultA,0x0, sizeof(resultA));
    exec_shell(command, resultA);
	
    if(strlen(resultA) != 0)
    {
        count = atoi(resultA);
        json::Value jsondisk; 
        for (int i = 1; i <= count; i++) 
        {
            sprintf(command, "%s %d" ,"collect_disk_util_info.sh INDEX", i);
            memset(resultA,0x0, sizeof(resultA));
            exec_shell(command, resultA);

            if(strlen(resultA) != 0)
            {		
                char tmp1[6][128];
                sscanf(resultA, "%s %s %s %s %s %s" ,  tmp1[0] , tmp1[1],  tmp1[2], tmp1[3], tmp1[4], tmp1[5]);
                jsondisk["DISK UTIL"]["ID"]                    = i;	
                jsondisk["DISK UTIL"]["Filesystem"]        =  tmp1[0];	
                jsondisk["DISK UTIL"]["Size"]                 =  tmp1[1];	
                jsondisk["DISK UTIL"]["Used"]                =  tmp1[2];	
                jsondisk["DISK UTIL"]["Avail"]                =  tmp1[3];	
                jsondisk["DISK UTIL"]["Use %"]              = tmp1[4];	
                jsondisk["DISK UTIL"]["Mounted on"]       = tmp1[5];	
                response["DISK USAGE INFO"].push_back(std::move(jsondisk));	
            }

        }
    }

}
#endif
#endif 
    response[constants::System::SKU] = system.get_sku();
    response[constants::Common::ASSET_TAG] = system.get_asset_tag();
    response[constants::System::INDICATOR_LED] = system.get_indicator_led();


    response[constants::System::BOOT][constants::System::BOOT_SOURCE_OVERRIDE_TARGET] =        system.get_boot_override_target().to_string();

    response[constants::System::BOOT][constants::System::BOOT_SOURCE_OVERRIDE_ENABLED] =        system.get_boot_override().to_string();
/*
    for (const auto& allowable : system.get_boot_override_supported()) {
        response[constants::System::BOOT][constants::System::BOOT_SOURCE_OVERRIDE_TARGET_ALLOWABLE_VALUES].
            push_back(allowable.to_string());
    }
*/
    response[constants::System::BOOT][constants::System::BOOT_SOURCE_OVERRIDE_MODE] =        system.get_boot_override_mode().to_string();

    std::string hash_computer_system_reset(constants::Common::HASH);
    hash_computer_system_reset.append(constants::System::COMPUTER_SYSTEM_RESET);
    response[constants::Common::ACTIONS][hash_computer_system_reset][constants::System::TARGET] =
        PathBuilder(req)
            .append(constants::Common::ACTIONS)
            .append(constants::System::COMPUTER_SYSTEM_RESET)
            .build();

    // do NOT remove, needed for PODM integration purposes
    response[constants::Common::OEM][constants::Common::RACKSCALE]
    [constants::System::DISCOVERY_STATE] = constants::System::BASIC;

    add_processors_summary(system, response);
    add_memory_summary(system, response);
    add_system_relations(system, response);
    make_children_links(req, response);


    /*For get Hostname/FQDN*/
    char command[256] = {0};
    char resultA[256] = {0};	
    sprintf(command, "%s" ,"hostname");
    memset(resultA,0x0, sizeof(resultA));
    exec_shell(command, resultA);
    
    if(strlen(resultA) != 0)
    {
    	resultA[strcspn(resultA, "\r\n")]=0;
    	response[constants::System::HOST_NAME] = resultA;
    }


    set_response(res, response);
}


void endpoint::System::patch(const server::Request& request, server::Response& response) {

    std::string agent_id{};
    std::string system_uuid{};
    std::string parent_uuid{};
    BootOverrideSupported override_supported{};

    // Gets necessary data from model
    auto system = model::Find<agent_framework::model::System>(request.params[PathParam::SYSTEM_ID]).get();

    agent_id = system.get_agent_id();
    system_uuid = system.get_uuid();
    parent_uuid = system.get_parent_uuid();
    override_supported = system.get_boot_override_supported();

    const auto& json = JsonValidator::validate_request_body<schema::SystemPatchSchema>(request);
    agent_framework::model::attribute::Attributes attributes{};

    if (json.is_member(constants::Common::ASSET_TAG)) {
        const auto& asset_tag = json[constants::Common::ASSET_TAG].as_string();
        attributes.set_value(agent_framework::model::literals::System::ASSET_TAG, asset_tag);
		/*Nick Added Begin: */
		char command[256] = {0};
		char resultA[256] = {0};
		sprintf(command, "echo %s > /etc/psme/ASSET_TAG", asset_tag.c_str());	
		exec_shell(command, resultA);
		system.set_asset_tag(asset_tag);	
		/*Nick Added End  : */
    }
/*
    if (json.is_member(constants::System::BOOT)) {
        const auto& boot_property = json[constants::System::BOOT];
        if (boot_property.is_member(constants::System::BOOT_SOURCE_OVERRIDE_ENABLED)) {
            const auto& boot_override = boot_property[constants::System::BOOT_SOURCE_OVERRIDE_ENABLED].as_string();
            attributes.set_value(agent_framework::model::literals::System::BOOT_OVERRIDE, boot_override);
        }
        if (boot_property.is_member(constants::System::BOOT_SOURCE_OVERRIDE_TARGET)) {
            const auto& boot_override_target = boot_property[constants::System::BOOT_SOURCE_OVERRIDE_TARGET].as_string();
            const auto boot_override_target_enum = BootOverrideTarget::from_string(boot_override_target);
            auto predicate = [&boot_override_target_enum](const BootOverrideTarget& type) {
                return boot_override_target_enum == type;
            };
            if (!std::any_of(override_supported.begin(), override_supported.end(), predicate)) {
                throw error::ServerException(
                    error::ErrorFactory::create_error_for_not_allowable_value(
                        "System does not support requested target.",
                        endpoint::PathBuilder(constants::System::BOOT)
                            .append(constants::System::BOOT_SOURCE_OVERRIDE_TARGET)
                            .build(),
                        boot_override_target,
                        endpoint::PathBuilder(constants::System::BOOT)
                            .append(constants::System::BOOT_SOURCE_OVERRIDE_TARGET_ALLOWABLE_VALUES)
                            .build()
                    )
                );
            }

            attributes.set_value(agent_framework::model::literals::System::BOOT_OVERRIDE_TARGET, boot_override_target);
        }
        if (boot_property.is_member(constants::System::BOOT_SOURCE_OVERRIDE_MODE)) {
            const auto& boot_mode = boot_property[constants::System::BOOT_SOURCE_OVERRIDE_MODE].as_string();
            attributes.set_value(agent_framework::model::literals::System::BOOT_OVERRIDE_MODE, boot_mode);
        }
    }

    if (!attributes.empty()) {
        agent_framework::model::requests::SetComponentAttributes
            set_component_attributes_request{system_uuid, attributes};

        const auto& gami_agent = psme::core::agent::AgentManager::get_instance()->get_agent(agent_id);

        auto set_system_attributes = [&, gami_agent] {
            // Call set component attribute method
            const auto& set_component_attributes_response = gami_agent->
                execute<agent_framework::model::responses::SetComponentAttributes>(set_component_attributes_request);

            const auto& result_statuses = set_component_attributes_response.get_statuses();
            if (!result_statuses.empty()) {
                const auto& error = error::ErrorFactory::create_error_from_set_component_attributes_results(
                    result_statuses, gami_to_rest_attributes);
                throw error::ServerException(error);
            }

            psme::rest::model::handler::HandlerManager::get_instance()->get_handler(
                agent_framework::model::enums::Component::System)->
                load(gami_agent,
                     parent_uuid,
                     agent_framework::model::enums::Component::Manager,
                     system_uuid,
                     false);

            // setting system boot options can change Network Device Function. So, we reload it:
            reload_network_device_function(gami_agent, system_uuid);
        };

        gami_agent->execute_in_transaction(set_system_attributes);
    }
*/
    get(request, response);
}

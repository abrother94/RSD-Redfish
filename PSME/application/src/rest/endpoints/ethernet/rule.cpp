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

#include "psme/rest/endpoints/ethernet/rule.hpp"
#include "psme/rest/validators/json_validator.hpp"
#include "psme/rest/validators/schemas/rule.hpp"
#include "psme/rest/server/error/error_factory.hpp"
#include "psme/rest/model/handlers/handler_manager.hpp"
#include "psme/rest/model/handlers/generic_handler_deps.hpp"
#include "psme/rest/model/handlers/generic_handler.hpp"
#include "psme/core/agent/agent_manager.hpp"

#include "agent-framework/module/requests/network.hpp"
#include "agent-framework/module/responses/network.hpp"
#include "agent-framework/module/requests/common.hpp"
#include "agent-framework/module/responses/common.hpp"



using namespace psme::rest;
using namespace psme::rest::validators;
using namespace psme::rest::error;
using namespace psme::rest::constants;
using namespace psme::rest::model::handler;
using namespace psme::core::agent;
using namespace agent_framework::module;
using namespace agent_framework::model;
using NetworkComponents = agent_framework::module::NetworkComponents;

namespace {
json::Value make_prototype() {
    json::Value r(json::Value::Type::OBJECT);

    r[Common::ODATA_CONTEXT] = "/redfish/v1/$metadata#EthernetSwitchACLRule.EthernetSwitchACLRule/"
        "Members/__SWITCH_ID__/ACLs/Members/__ACL_ID__/Rules/Members/$entity";
    r[Common::ODATA_ID] = json::Value::Type::NIL;
    r[Common::ODATA_TYPE] = "#EthernetSwitchACLRule.v1_0_0.EthernetSwitchACLRule";

    r[Common::ID] = json::Value::Type::NIL;
    r[Common::NAME] = "ACL Rule";
    r[Common::DESCRIPTION] = "Access Control List Rule";

    r[Rule::RULE_ID] = json::Value::Type::NIL;
    r[Rule::ACTION] = json::Value::Type::NIL;
    r[Rule::FORWARD_MIRROR_INTERFACE] = json::Value::Type::NIL;
    r[Rule::MIRROR_PORT_REGION] = json::Value::Type::ARRAY;
    r[Rule::MIRROR_TYPE] = json::Value::Type::NIL;

    json::Value condition;
    condition[Rule::IP_SOURCE] = json::Value::Type::NIL;
    condition[Rule::IP_DESTINATION] = json::Value::Type::NIL;
    condition[Rule::MAC_SOURCE] = json::Value::Type::NIL;
    condition[Rule::MAC_DESTINATION] = json::Value::Type::NIL;
    condition[Rule::VLAN_ID] = json::Value::Type::NIL;
    condition[Rule::L4_SOURCE_PORT] = json::Value::Type::NIL;
    condition[Rule::L4_DESTINATION_PORT] = json::Value::Type::NIL;
    condition[Rule::L4_PROTOCOL] = json::Value::Type::NIL;
    r[Rule::CONDITION] = std::move(condition);

    r[Common::OEM] = json::Value::Type::OBJECT;
    r[Common::LINKS] = json::Value::Type::OBJECT;

    return r;
}

#if 0
void set_condition(const AclRule& rule, json::Value& r) {
    if (rule.get_source_ip().get_address().has_value()) {
        r[Rule::CONDITION][constants::Rule::IP_SOURCE][constants::Rule::IP_ADDRESS] =
            rule.get_source_ip().get_address();
        r[Rule::CONDITION][constants::Rule::IP_SOURCE][constants::Rule::MASK] =
            rule.get_source_ip().get_mask();
    }
    if (rule.get_destination_ip().get_address().has_value()) {
        r[Rule::CONDITION][constants::Rule::IP_DESTINATION][constants::Rule::IP_ADDRESS] =
            rule.get_destination_ip().get_address();
        r[Rule::CONDITION][constants::Rule::IP_DESTINATION][constants::Rule::MASK] =
            rule.get_destination_ip().get_mask();
    }
    if (rule.get_source_mac().get_address().has_value()) {
        r[Rule::CONDITION][constants::Rule::MAC_SOURCE][constants::Common::MAC_ADDRESS] =
            rule.get_source_mac().get_address();
        r[Rule::CONDITION][constants::Rule::MAC_SOURCE][constants::Rule::MASK] =
            rule.get_source_mac().get_mask();
    }
    if (rule.get_destination_mac().get_address().has_value()) {
        r[Rule::CONDITION][constants::Rule::MAC_DESTINATION][constants::Common::MAC_ADDRESS] =
            rule.get_destination_mac().get_address();
        r[Rule::CONDITION][constants::Rule::MAC_DESTINATION][constants::Rule::MASK] =
            rule.get_destination_mac().get_mask();
    }
    if (rule.get_vlan_id().get_id().has_value()) {
        r[Rule::CONDITION][constants::Rule::VLAN_ID][constants::Common::ID] =
            rule.get_vlan_id().get_id();
        r[Rule::CONDITION][constants::Rule::VLAN_ID][constants::Rule::MASK] =
            rule.get_vlan_id().get_mask();
    }
    if (rule.get_source_port().get_port().has_value()) {
        r[Rule::CONDITION][constants::Rule::L4_SOURCE_PORT][constants::Rule::PORT] =
            rule.get_source_port().get_port();
        r[Rule::CONDITION][constants::Rule::L4_SOURCE_PORT][constants::Rule::MASK] =
            rule.get_source_port().get_mask();
    }
    if (rule.get_destination_port().get_port().has_value()) {
        r[Rule::CONDITION][constants::Rule::L4_DESTINATION_PORT][constants::Rule::PORT] =
            rule.get_destination_port().get_port();
        r[Rule::CONDITION][constants::Rule::L4_DESTINATION_PORT][constants::Rule::MASK] =
            rule.get_destination_port().get_mask();
    }

    r[Rule::CONDITION][constants::Rule::L4_PROTOCOL] = rule.get_protocol();
}


void set_region(const AclRule& rule, json::Value& r) {
    const auto& ports = rule.get_mirrored_ports();
    for (const auto& port : ports) {
        json::Value port_link;
        port_link[Common::ODATA_ID] = endpoint::utils::get_component_url(enums::Component::EthernetSwitchPort, port);
        r[Rule::MIRROR_PORT_REGION].push_back(std::move(port_link));
    }
}


void fill_condition(const json::Value& json, attribute::Attributes& attributes) {

    std::vector<std::string> valid_conditions{
        Rule::IP_SOURCE,
        Rule::IP_DESTINATION,
        Rule::MAC_SOURCE,
        Rule::MAC_DESTINATION,
        Rule::VLAN_ID,
        Rule::L4_SOURCE_PORT,
        Rule::L4_DESTINATION_PORT,
        Rule::L4_PROTOCOL
    };

    for (const auto& field : valid_conditions) {
        if (json.is_member(field)) {
            if (Rule::IP_SOURCE == field) {
                attributes.set_value(literals::AclRule::SOURCE_IP, attribute::AclAddress(
                    json[field][Rule::IP_ADDRESS],
                    json[field][Rule::MASK]).to_json());
            }
            if (Rule::IP_DESTINATION == field) {
                attributes.set_value(literals::AclRule::DESTINATION_IP, attribute::AclAddress(
                    json[field][Rule::IP_ADDRESS],
                    json[field][Rule::MASK]).to_json());
            }
            else if (Rule::MAC_SOURCE == field) {
                attributes.set_value(literals::AclRule::SOURCE_MAC, attribute::AclAddress(
                    json[field][Common::MAC_ADDRESS],
                    json[field][Rule::MASK]).to_json());
            }
            else if (Rule::MAC_DESTINATION == field) {
                attributes.set_value(literals::AclRule::DESTINATION_MAC, attribute::AclAddress(
                    json[field][Common::MAC_ADDRESS],
                    json[field][Rule::MASK]).to_json());
            }
            else if (Rule::L4_SOURCE_PORT == field) {
                attributes.set_value(literals::AclRule::SOURCE_L4_PORT, attribute::AclPort(
                    json[field][Rule::PORT],
                    json[field][Rule::MASK]).to_json());
            }
            else if (Rule::L4_DESTINATION_PORT == field) {
                attributes.set_value(literals::AclRule::DESTINATION_L4_PORT, attribute::AclPort(
                    json[field][Rule::PORT],
                    json[field][Rule::MASK]).to_json());
            }
            else if (Rule::VLAN_ID == field) {
                attributes.set_value(literals::AclRule::VLAN_ID, attribute::AclVlanId(
                    json[field][Common::ID],
                    json[field][Rule::MASK]).to_json());
            }
            else if (Rule::L4_PROTOCOL == field) {
                attributes.set_value(literals::AclRule::PROTOCOL, OptionalField<std::uint32_t>(json[field]));
            }
        }
    }
}

attribute::Attributes fill_attributes(const json::Value& parsed_json, const AclRule& rule) {
    using AclAction = agent_framework::model::enums::AclAction;

    attribute::Attributes attributes;
    auto action = rule.get_action();

    if (parsed_json.is_member(Rule::ACTION)) {
        action = OptionalField<AclAction>(parsed_json[Rule::ACTION]);
        attributes.set_value(literals::AclRule::ACTION, parsed_json[Rule::ACTION].as_string());
    }
    if (parsed_json.is_member(Rule::RULE_ID)) {
        // Workaround for GAMI - REST spec mismatch:
        THROW(agent_framework::exceptions::NotImplemented, "rest",
              "Setting 'RuleId' is not implemented in the network agent.");
    }
    if (parsed_json.is_member(Rule::MIRROR_TYPE)) {
        attributes.set_value(literals::AclRule::MIRROR_TYPE, parsed_json[Rule::MIRROR_TYPE].as_string());
    }
    if (parsed_json.is_member(Rule::FORWARD_MIRROR_INTERFACE)) {
        const auto port_url = parsed_json[Rule::FORWARD_MIRROR_INTERFACE][Common::ODATA_ID].as_string();
        attributes.set_value(literals::AclRule::FORWARD_MIRROR_PORT, endpoint::utils::get_port_uuid_from_url(port_url));
    }
    if (parsed_json.is_member(Rule::MIRROR_PORT_REGION)) {
        attribute::Array<std::string> port_array{};
        for (const auto& port : parsed_json[Rule::MIRROR_PORT_REGION].as_array()) {
            const auto port_url = port[Common::ODATA_ID].as_string();
            port_array.add_entry(endpoint::utils::get_port_uuid_from_url(port_url));
        }
        attributes.set_value(literals::AclRule::MIRRORED_PORTS, port_array.to_json());
    }
    if (parsed_json.is_member(Rule::CONDITION)) {
        fill_condition(parsed_json[Rule::CONDITION], attributes);
    }

    if (AclAction::Mirror == action || AclAction::Forward == action) {
        // If ForwardMirrorInterface is (not present in json or model) or is (present in json and set to null)
        if ((!parsed_json.is_member(Rule::FORWARD_MIRROR_INTERFACE) &&
             !rule.get_forward_mirror_port().has_value()) ||
            (parsed_json.is_member(Rule::FORWARD_MIRROR_INTERFACE) &&
             parsed_json[Rule::FORWARD_MIRROR_INTERFACE].is_null())) {
            throw ServerException(ErrorFactory::create_property_missing_error(
                constants::Rule::FORWARD_MIRROR_INTERFACE,
                "Mandatory field is missing for " + std::string(action.value().to_string()) + " action."
            ));
        }
    }
    if (agent_framework::model::enums::AclAction::Mirror == action) {
        // If MirrorType is (not present in json or model) or is (present in json and set to null)
        if ((!parsed_json.is_member(Rule::MIRROR_TYPE) &&
             !rule.get_forward_mirror_port().has_value()) ||
            (parsed_json.is_member(Rule::MIRROR_TYPE) &&
             parsed_json[Rule::MIRROR_TYPE].is_null())) {
            throw ServerException(ErrorFactory::create_property_missing_error(
                constants::Rule::MIRROR_TYPE,
                "Mandatory field is missing for " + std::string(action.value().to_string()) + " action."
            ));
        }
    }

    return attributes;
}

static const std::map<std::string, std::string> gami_to_rest_attributes = {
    {agent_framework::model::literals::AclRule::ACTION, constants::Rule::ACTION},
    {agent_framework::model::literals::AclRule::FORWARD_MIRROR_PORT, constants::Rule::FORWARD_MIRROR_INTERFACE},
    {agent_framework::model::literals::AclRule::MIRRORED_PORTS, constants::Rule::MIRROR_PORT_REGION},
    {agent_framework::model::literals::AclRule::MIRROR_TYPE, constants::Rule::MIRROR_TYPE},
    {agent_framework::model::literals::AclRule::SOURCE_IP, endpoint::PathBuilder(constants::Rule::CONDITION)
                                                               .append(constants::Rule::IP_SOURCE).build()},
    {agent_framework::model::literals::AclRule::DESTINATION_IP, endpoint::PathBuilder(constants::Rule::CONDITION)
                                                               .append(constants::Rule::IP_DESTINATION).build()},
    {agent_framework::model::literals::AclRule::SOURCE_MAC, endpoint::PathBuilder(constants::Rule::CONDITION)
                                                               .append(constants::Rule::MAC_SOURCE).build()},
    {agent_framework::model::literals::AclRule::DESTINATION_MAC, endpoint::PathBuilder(constants::Rule::CONDITION)
                                                               .append(constants::Rule::MAC_DESTINATION).build()},
    {agent_framework::model::literals::AclRule::VLAN_ID, endpoint::PathBuilder(constants::Rule::CONDITION)
                                                               .append(constants::Rule::VLAN_ID).build()},
    {agent_framework::model::literals::AclRule::SOURCE_L4_PORT, endpoint::PathBuilder(constants::Rule::CONDITION)
                                                               .append(constants::Rule::L4_SOURCE_PORT).build()},
    {agent_framework::model::literals::AclRule::DESTINATION_L4_PORT, endpoint::PathBuilder(constants::Rule::CONDITION)
                                                               .append(constants::Rule::L4_DESTINATION_PORT).build()},
    {agent_framework::model::literals::AclRule::PROTOCOL, endpoint::PathBuilder(constants::Rule::CONDITION)
                                                               .append(constants::Rule::L4_PROTOCOL).build()},
};
#endif
}


endpoint::Rule::Rule(const std::string& path) : EndpointBase(path) {}


endpoint::Rule::~Rule() {}


void endpoint::Rule::get(const server::Request& req, server::Response& res) {
    auto r = ::make_prototype();

    r[Common::ODATA_CONTEXT] = std::regex_replace(
        r[Common::ODATA_CONTEXT].as_string(),
        std::regex("__SWITCH_ID__"),
        req.params[PathParam::ETHERNET_SWITCH_ID]);

    r[Common::ODATA_CONTEXT] = std::regex_replace(
        r[Common::ODATA_CONTEXT].as_string(),
        std::regex("__ACL_ID__"),
        req.params[PathParam::ACL_ID]);

    r[Common::ODATA_ID] = PathBuilder(req).build();
    r[Common::ID] = req.params[PathParam::RULE_ID];
    r[Common::NAME] = constants::Rule::RULE + req.params[PathParam::RULE_ID];
#if 0
    const auto rule =
        psme::rest::model::Find<agent_framework::model::AclRule>(req.params[PathParam::RULE_ID])
            .via<agent_framework::model::EthernetSwitch>(req.params[PathParam::ETHERNET_SWITCH_ID])
            .via<agent_framework::model::Acl>(req.params[PathParam::ACL_ID])
            .get();

    r[constants::Rule::RULE_ID] = rule.get_rule_id();
    r[constants::Rule::ACTION] = rule.get_action();
    if (rule.get_forward_mirror_port().has_value()) {
        r[constants::Rule::FORWARD_MIRROR_INTERFACE][Common::ODATA_ID] =
            endpoint::utils::get_component_url(enums::Component::EthernetSwitchPort, rule.get_forward_mirror_port());
    }
    r[constants::Rule::MIRROR_TYPE] = rule.get_mirror_type();
#else

    char resultA[512] = {0};	
    char command[256] = {0};
    char tmp1[20][128];

    int iACL_ID = std::stoi(req.params[PathParam::ACL_ID]);
    int iRULE_ID = std::stoi(req.params[PathParam::RULE_ID]);

    r[constants::Rule::RULE_ID] = iRULE_ID;

    sprintf(command, "uci get RULE.RULE%d_%d", iACL_ID, iRULE_ID);  //Create new rule with ACL ID but not have rule index //
    memset(resultA,0x0, sizeof(resultA));
    exec_shell(command, resultA);
    
    if(!strcmp(resultA ,""))
    {
        res.set_status(server::status_2XX::NO_CONTENT);
        return;
    }

    if (  (iRULE_ID <= RULE_MAX) && ( iACL_ID <= ACL_MAX) )                      // MAX RULE ID == 10 //
    {

        sprintf(command, "rule.sh get rule_from_acl %d %d", iACL_ID, iRULE_ID);  //Create new rule with ACL ID but not have rule index //
        memset(resultA,0x0, sizeof(resultA));
        exec_shell(command, resultA);
		
        if(strlen(resultA) != 0)
        {
//Action IPSource IPSourceMASK IPDestination IPDestinationMASK MACSource MACSourceMASK
//MACDestination MACDestinationMASK VLANID VLANIDMASK L4SourcePort L4SourcePortMASK
//L4DestPort L4DestPortMASK L4Protocol ForwardMirrorInterface MirrorPortRegion MirrorType
		
            sscanf(resultA, "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s" ,  
            tmp1[0] , tmp1[1], tmp1[2], tmp1[3], tmp1[4], tmp1[5], tmp1[6], tmp1[7] , tmp1[8], tmp1[9],
            tmp1[10] , tmp1[11], tmp1[12], tmp1[13], tmp1[14], tmp1[15], tmp1[16], tmp1[17] , tmp1[18]);

//Action
           if (strlen(tmp1[0])) {
               r[constants::Rule::ACTION] = tmp1[0];
           }

           if ( strlen(tmp1[1]) && strlen(tmp1[2]) ) {
//IPSource	
               if(!strcmp(tmp1[1] ,"NA" ))
                   r[constants::Rule::CONDITION][constants::Rule::IP_SOURCE][constants::Rule::IP_ADDRESS] = json::Value::Type::NIL ;
               else
                   r[constants::Rule::CONDITION][constants::Rule::IP_SOURCE][constants::Rule::IP_ADDRESS] = tmp1[1] ;
			   
//IPSourceMASK
               if(!strcmp(tmp1[2] ,"NA" ))
                   r[constants::Rule::CONDITION][constants::Rule::IP_SOURCE][constants::Rule::MASK] = json::Value::Type::NIL;
               else
                   r[constants::Rule::CONDITION][constants::Rule::IP_SOURCE][constants::Rule::MASK] = tmp1[2];
           }
		   
           if ( strlen(tmp1[3]) && strlen(tmp1[4]) ) {
//IPDestination		 

               if(!strcmp(tmp1[3] ,"NA" ))
                   r[constants::Rule::CONDITION][constants::Rule::IP_DESTINATION][constants::Rule::IP_ADDRESS] = json::Value::Type::NIL ;		   	
               else
                   r[constants::Rule::CONDITION][constants::Rule::IP_DESTINATION][constants::Rule::IP_ADDRESS] = tmp1[3] ;
//IPDestinationMASK

               if(!strcmp(tmp1[4] ,"NA" ))
                   r[constants::Rule::CONDITION][constants::Rule::IP_DESTINATION][constants::Rule::MASK] = json::Value::Type::NIL ;		   	
               else			   	
                   r[constants::Rule::CONDITION][constants::Rule::IP_DESTINATION][constants::Rule::MASK] = tmp1[4] ;
           }
		   
           if ( strlen(tmp1[5]) && strlen(tmp1[6]) ) {
//MACSource		
               if(!strcmp(tmp1[5] ,"NA" ))
                   r[constants::Rule::CONDITION][constants::Rule::MAC_SOURCE][constants::Common::MAC_ADDRESS] = json::Value::Type::NIL;
               else
                   r[constants::Rule::CONDITION][constants::Rule::MAC_SOURCE][constants::Common::MAC_ADDRESS] = tmp1[5] ;

//MACSourceMASK
               if(!strcmp(tmp1[6] ,"NA" ))
                   r[constants::Rule::CONDITION][constants::Rule::MAC_SOURCE][constants::Rule::MASK] = json::Value::Type::NIL ;
               else
                   r[constants::Rule::CONDITION][constants::Rule::MAC_SOURCE][constants::Rule::MASK] = tmp1[6] ;
           }
		   
           if ( strlen(tmp1[7]) && strlen(tmp1[8]) ) {
//MACDestination		
               if(!strcmp(tmp1[7] ,"NA" ))
                   r[constants::Rule::CONDITION][constants::Rule::MAC_DESTINATION][constants::Common::MAC_ADDRESS] = json::Value::Type::NIL ;
               else
                   r[constants::Rule::CONDITION][constants::Rule::MAC_DESTINATION][constants::Common::MAC_ADDRESS] = tmp1[7] ;

//MACDestinationMASK
               if(!strcmp(tmp1[8] ,"NA" ))
                   r[constants::Rule::CONDITION][constants::Rule::MAC_DESTINATION][constants::Rule::MASK] = json::Value::Type::NIL ;
               else
                   r[constants::Rule::CONDITION][constants::Rule::MAC_DESTINATION][constants::Rule::MASK] = tmp1[8] ;

           }
		   
           if ( strlen(tmp1[9]) && strlen(tmp1[10]) ) {
//VLANID	
               if(!strcmp(tmp1[9] ,"NA" ))
               {
                   r[constants::Rule::CONDITION][constants::Rule::VLAN_ID][constants::Common::ID] = json::Value::Type::NIL ;	
//VLANIDMASK			   	
                   r[constants::Rule::CONDITION][constants::Rule::VLAN_ID][constants::Rule::MASK] = json::Value::Type::NIL ;				   
               }
		else
		{
                   r[constants::Rule::CONDITION][constants::Rule::VLAN_ID][constants::Common::ID] = atoi(tmp1[9]) ;
//VLANIDMASK			   	
                   unsigned int intVal;
                   sscanf(tmp1[10], "%x", &intVal);
                   r[constants::Rule::CONDITION][constants::Rule::VLAN_ID][constants::Rule::MASK] = intVal ;				   
		}
           }
		   
           if ( strlen(tmp1[11]) && strlen(tmp1[12]) ) {
//L4SourcePort		

               if(!strcmp(tmp1[11] ,"NA" ))
               {
                   r[constants::Rule::CONDITION][constants::Rule::L4_SOURCE_PORT][constants::Rule::PORT] = json::Value::Type::NIL ;
//L4SourcePortMASK
                   r[constants::Rule::CONDITION][constants::Rule::L4_SOURCE_PORT][constants::Rule::MASK] = json::Value::Type::NIL ;				   
               }
		 else
		 {
                   r[constants::Rule::CONDITION][constants::Rule::L4_SOURCE_PORT][constants::Rule::PORT] = atoi(tmp1[11]) ;
//L4SourcePortMASK			   
                   unsigned int intVal;
                   sscanf(tmp1[12], "%x", &intVal);	
                   r[constants::Rule::CONDITION][constants::Rule::L4_SOURCE_PORT][constants::Rule::MASK] = intVal ;			   
		 }
           }
		   
           if ( strlen(tmp1[13]) && strlen(tmp1[14]) ) {
//L4DestPort	
               if(!strcmp(tmp1[13] ,"NA" ))
               {
                   r[constants::Rule::CONDITION][constants::Rule::L4_DESTINATION_PORT][constants::Rule::PORT] = json::Value::Type::NIL ;
//L4DestPortMASK
                   r[constants::Rule::CONDITION][constants::Rule::L4_DESTINATION_PORT][constants::Rule::MASK] = json::Value::Type::NIL ;		   					   
               }
               else
               {
                   r[constants::Rule::CONDITION][constants::Rule::L4_DESTINATION_PORT][constants::Rule::PORT] = atoi(tmp1[13]) ;
//L4DestPortMASK
                   unsigned int intVal;
                   sscanf(tmp1[14], "%x", &intVal);
                   r[constants::Rule::CONDITION][constants::Rule::L4_DESTINATION_PORT][constants::Rule::MASK] = intVal ;
				   
               }			   	
           }

           if ( strlen(tmp1[16]) ){
//Forward_mirror_interface		   	
               int fport = atoi(tmp1[16]) ;	   
               char PATH_ID[128];
               sprintf(PATH_ID,"/redfish/v1/EthernetSwitches/1/Ports/%d", fport);
               json::Value link;
               link[Common::ODATA_ID] = PATH_ID;

               if(fport == 0)
                   r[constants::Rule::FORWARD_MIRROR_INTERFACE]= json::Value::Type::NIL;
               else
                   r[constants::Rule::FORWARD_MIRROR_INTERFACE].push_back(std::move(link));
           }

//Mirror_regions	
           if ( strlen(tmp1[17]) && !strcmp(tmp1[17] ,"NA" ))
           {
               r[constants::Rule::MIRROR_PORT_REGION] = json::Value::Type::NIL;
           }
           else
           {
               unsigned long int intVal;
               sscanf(tmp1[17], "%lx", &intVal);

               sprintf(command, " psme.sh get max_port_num");
               memset(resultA,0x0, sizeof(resultA));
               exec_shell(command, resultA);
           
               if(strlen(resultA) != 0)
               {
                    int Max_port = atoi(resultA);
				   
                   for ( int i = 1 ; i <= Max_port; i++) 
                   {
                       if ((1UL << i) & intVal)
                       {
                           char PATH_ID[128];
                           sprintf(PATH_ID,"/redfish/v1/EthernetSwitches/1/Ports/%d", i);
                           json::Value link;
                           link[Common::ODATA_ID] = PATH_ID;
                           r[constants::Rule::MIRROR_PORT_REGION].push_back(std::move(link));
                       }
                   }
               }
			   
		   

           }

//Mirror_type	
           if ( strlen(tmp1[18]) )
           {
               if(!strcmp(tmp1[18] ,"NA" ))
                   r[constants::Rule::MIRROR_TYPE] = json::Value::Type::NIL;   	
               else
                   r[constants::Rule::MIRROR_TYPE] = tmp1[18];
           }   
        }
        set_response(res, r);
    }
    else
        res.set_status(server::status_5XX::SERVICE_UNAVAILABLE);

    //::set_region(rule, r);
    //::set_condition(rule, r);
#endif

}


void endpoint::Rule::del(const server::Request& req, server::Response& res) {
#if 0
    auto rule = psme::rest::model::Find<agent_framework::model::AclRule>(req.params[PathParam::RULE_ID])
        .via<agent_framework::model::EthernetSwitch>(req.params[PathParam::ETHERNET_SWITCH_ID])
        .via<agent_framework::model::Acl>(req.params[PathParam::ACL_ID])
        .get();

    auto delete_acl_rule_request = requests::DeleteAclRule(rule.get_uuid());

    const auto& agent = psme::core::agent::AgentManager::get_instance()->get_agent(rule.get_agent_id());

    auto delete_rule = [&, agent] {
        // try removing ACL from agent's model
        agent->execute<responses::DeleteAclRule>(delete_acl_rule_request);

        // remove the resource from application's model
        HandlerManager::get_instance()->get_handler(enums::Component::AclRule)->remove(rule.get_uuid());

        res.set_status(server::status_2XX::NO_CONTENT);
    };
    agent->execute_in_transaction(delete_rule);
#else

    char resultA[256] = {0};	
    char command[256] = {0};

    int iACL_ID = std::stoi(req.params[PathParam::ACL_ID]);
    int iRULE_ID = std::stoi(req.params[PathParam::RULE_ID]);

    if (  (iRULE_ID <= RULE_MAX) && ( iACL_ID <= ACL_MAX) )                      // MAX RULE ID == 10 //
    {
        sprintf(command, "acl.sh set del_acl_rule %d %d", iACL_ID, iRULE_ID);  //Create new rule with ACL ID but not have rule index //
        memset(resultA,0x0, sizeof(resultA));
        exec_shell(command, resultA);
//Re init ACL
        sprintf(command, "acl_init.sh clean; acl_init.sh start");
        memset(resultA,0x0, sizeof(resultA));
        exec_shell(command, resultA);
		
        res.set_status(server::status_2XX::NO_CONTENT);
    }
    else
        res.set_status(server::status_5XX::SERVICE_UNAVAILABLE);

	
#endif
}

//string USE "NA" as null, \"\" as original one , number 0 as original one, 30600 as null //
void endpoint::Rule::patch(const server::Request& request, server::Response& response) {

    const auto json = JsonValidator::validate_request_body<schema::RulePatchSchema>(request);

    int iACL_ID = std::stoi(request.params[PathParam::ACL_ID]);
    int rule_id = std::stoi(request.params[PathParam::RULE_ID]);

    char resultA[256] = {0};	
    char command[256] = {0};

    char  t_SrcIP[32]="\"\"";
    char  t_SrcIP_Mask[32]="\"\"";
    char  t_DstIP[32]="\"\"";
    char  t_DstIP_Mask[32]="\"\"";
    char  t_SrcMAC[32]="\"\"";
    char  t_SrcMAC_Mask[32]="\"\"";
    char  t_DstMAC [32]="\"\"";
    char  t_DstMAC_Mask [32]="\"\"";
    char  t_Action [32]="\"\"";
    char  t_MirrorType [32]="\"\"";
    char  h_mirrorport[128] = "\"\"";
	
    unsigned long long  mirrorports=0;
    unsigned long long  DstPort  = 0;		
    uint32_t  DstPortMask  = 0;		
	
    unsigned long long  SrcPort = 0;
    uint32_t  SrcPortMask = 0;
	
    uint32_t  Vlan_id  = 0;
    uint32_t  Vlan_idMask  = 0;

    if (  (rule_id <= RULE_MAX) && (iACL_ID <= ACL_MAX)) 
    {
        int ForwardMirrorPort = 0;
        std::string temp_path;
       
        /*Get from PATCH JASON*/
        if (json.is_member("Action"))
        {
	     const string&   Action = json["Action"].as_string();
            if(!strcmp(Action.c_str(),"Deny"))
                sprintf(t_Action, "%s", "Deny");
            else if (!strcmp(Action.c_str(),"Mirror"))
                sprintf(t_Action, "%s", "Mirror");	  //SOC do not support mirror egress 		
            else if (!strcmp(Action.c_str(),"Forward"))			
                sprintf(t_Action, "%s", "Forward");	  
            else if (!strcmp(Action.c_str(),"Permit"))			
                sprintf(t_Action, "%s", "Permit");	   		
            else
                sprintf(t_Action, "%s", "Deny");
        }

        if (json["Condition"].is_member("IPSource") )
        {
            if (json["Condition"]["IPSource"].is_member("IPv4Address") )
            {
                const string&  SrcIP = json["Condition"]["IPSource"]["IPv4Address"].as_string();
                if(SrcIP.length() != 0)
                {
                    sprintf(t_SrcIP,"%s", SrcIP.c_str());
                }	
            }
            else
                sprintf(t_SrcIP,"%s", "NA");			
        }

        if (json["Condition"].is_member("IPSource") )
        {
            if (json["Condition"]["IPSource"].is_member("Mask") )
            {
                const string&  SrcIPMask = json["Condition"]["IPSource"]["Mask"].as_string();
                if(SrcIPMask.length() != 0)
                {
                    sprintf(t_SrcIP_Mask,"%s", SrcIPMask.c_str());  
                }			
            }
    	     else
                sprintf(t_SrcIP_Mask,"%s", "NA");				
        }

        if (json["Condition"].is_member("IPDestination") )
        {
            if (json["Condition"]["IPDestination"].is_member("IPv4Address") )
            {
                const string&  DstIP  = json["Condition"]["IPDestination"]["IPv4Address"].as_string();
                if(DstIP.length() != 0)
                {
                    sprintf(t_DstIP,"%s", DstIP.c_str());
                }	 	
            }
    	     else
                sprintf(t_DstIP,"%s", "NA");			
        }

        if (json["Condition"].is_member("IPDestination") )
        {
            if (json["Condition"]["IPDestination"].is_member("Mask") )
            {
                const string&  DstIPMask = json["Condition"]["IPDestination"]["Mask"].as_string();
                if(DstIPMask.length() != 0)
                {
                    sprintf(t_DstIP_Mask,"%s",  DstIPMask.c_str()); 
                }				
            }
    	     else
                sprintf(t_DstIP_Mask,"%s", "NA");				
        }

        if (json["Condition"].is_member("MACSource") )
        {
            if (json["Condition"]["MACSource"].is_member("MACAddress") )
            {
                const string&  SrcMAC = json["Condition"]["MACSource"]["MACAddress"].as_string();
    			
                if(SrcMAC.length() != 0)
                {
                    sprintf(t_SrcMAC,"%s", SrcMAC.c_str());
                }	
            }
    	     else
                sprintf(t_SrcMAC,"%s", "NA");			
        }

        if (json["Condition"].is_member("MACSource") )
        {
            if (json["Condition"]["MACSource"].is_member("Mask") )
            {
                const string&  SrcMACMask = json["Condition"]["MACSource"]["Mask"].as_string();
    			
                if(SrcMACMask.length() != 0)
                {
                    sprintf(t_SrcMAC_Mask,"%s", SrcMACMask.c_str());
                }	
            }
    	     else
                sprintf(t_SrcMAC_Mask,"%s", "NA");				
        }

        if (json["Condition"].is_member("MACDestination") )
        {
            if (json["Condition"]["MACDestination"].is_member("MACAddress") )
            {
                const string&  DstMAC = json["Condition"]["MACDestination"]["MACAddress"].as_string();
    		
                if(DstMAC.length() != 0)
                {
                    sprintf(t_DstMAC,"%s", DstMAC.c_str());
                }				
            }
    	     else
                sprintf(t_DstMAC,"%s", "NA");			
        }

        if (json["Condition"].is_member("MACDestination") )
        {
            if (json["Condition"]["MACDestination"].is_member("Mask") )
            {
                const string&  DstMACMask = json["Condition"]["MACDestination"]["Mask"].as_string();
    		
                if(DstMACMask.length() != 0)
                {
                    sprintf(t_DstMAC_Mask,"%s",  DstMACMask.c_str()); 
                }				
            }
    	     else
                    sprintf(t_DstMAC_Mask,"%s", "NA");			
        }
		
        if (json.is_member("MirrorType") )
        {
            const string&  MirrorType  = json["MirrorType"].as_string();
            if(MirrorType.length() == 0 )
                sprintf(t_MirrorType,"%s", "NA");
            else
                sprintf(t_MirrorType,"%s", MirrorType.c_str());  // Only support Ingress        
        }

        if (json["Condition"].is_member("L4DestinationPort") )
        {
            if (json["Condition"]["L4DestinationPort"].is_member("Port") )
            {		
                DstPort  = json["Condition"]["L4DestinationPort"]["Port"].as_uint64();			
            }
            else
                DstPort  = 30600;//Magic number
        }

        if (json["Condition"].is_member("L4DestinationPort") )
        {
            if (json["Condition"]["L4DestinationPort"].is_member("Mask") )
            {	
                DstPortMask  = json["Condition"]["L4DestinationPort"]["Mask"].as_int();	 
            }
            else
                DstPortMask  = 30600;//Magic number		
        }

        if (json["Condition"].is_member("L4SourcePort") )
        {
            if (json["Condition"]["L4SourcePort"].is_member("Port") )
            {
    	         SrcPort  = json["Condition"]["L4SourcePort"]["Port"].as_uint64();	 
            }
            else
                SrcPort  = 30600;//Magic number				
        }

        if (json["Condition"].is_member("L4SourcePort") )
        {
            if (json["Condition"]["L4SourcePort"].is_member("Mask") )
            {
                SrcPortMask  = json["Condition"]["L4SourcePort"]["Mask"].as_int();
            }
            else
                SrcPortMask  = 30600;//Magic number			
        }

        if (json["Condition"].is_member("VLANId") )
        {
            if (json["Condition"]["VLANId"].is_member("Id") )
            {
    	         Vlan_id  = json["Condition"]["VLANId"]["Id"].as_int();
            }
            else
                Vlan_id  = 30600;//Magic number			
        }

        if (json["Condition"].is_member("VLANId") )
        {
            if (json["Condition"]["VLANId"].is_member("Mask") )
            {
                Vlan_idMask  = json["Condition"]["VLANId"]["Mask"].as_int();
            }
            else
                Vlan_idMask  = 30600;//Magic number				
        }

        if ( json["ForwardMirrorInterface"].is_member("@odata.id") )
        {
            const string&  ForwardMirroInterface = json["ForwardMirrorInterface"]["@odata.id"].as_string();
        
            if(ForwardMirroInterface.length() != 0)
            {
               temp_path= std::regex_replace(   ForwardMirroInterface.c_str(),    std::regex("/redfish/v1/EthernetSwitches/1/Ports/"), "");
            }
			
            ForwardMirrorPort = atoi(temp_path.c_str());
        }

        json::Value schema({
            JsonValidator::mandatory(Common::ODATA_ID,
                JsonValidator::has_type(JsonValidator::STRING_TYPE))
        });		
		
        for (const auto& key : json["MirrorPortRegion"]) 
        {
            const auto port_url = JsonValidator::validate_request_body(key, schema)[Common::ODATA_ID].as_string();
            temp_path= std::regex_replace(   port_url.c_str() ,    std::regex("/redfish/v1/EthernetSwitches/1/Ports/"), "");
            mirrorports |= (1ULL << atoi(temp_path.c_str()) );
	     sprintf(h_mirrorport,"0x%llx", mirrorports);
        }	
		
//TODO, opional MASK //

//Create new rule with ACL ID
//Action IPSource IPSourceMASK IPDestination IPDestinationMASK MACSource MACSourceMASK
//MACDestination MACDestinationMASK VLANID VLANIDMASK L4SourcePort L4SourcePortMASK
//L4DestPort L4DestPortMASK L4Protocol ForwardMirrorInterface MirrorPortRegion MirrorType
 
        sprintf(command, "rule.sh set rule_to_acl  %d %d %s %s %s %s %s %s %s %s %s %d 0x%x %llu 0x%x %llu 0x%x NA %d %s %s ",	
        iACL_ID, rule_id, t_Action, t_SrcIP, t_SrcIP_Mask, t_DstIP , t_DstIP_Mask, t_SrcMAC, t_SrcMAC_Mask, t_DstMAC, t_DstMAC_Mask , Vlan_id, Vlan_idMask ,SrcPort, SrcPortMask,DstPort ,DstPortMask, ForwardMirrorPort, h_mirrorport , t_MirrorType); 

        memset(resultA,0x0, sizeof(resultA));
        exec_shell(command, resultA);
		
    }

    get(request, response);

}

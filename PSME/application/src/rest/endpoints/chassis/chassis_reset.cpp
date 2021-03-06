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

#include "psme/core/agent/agent_manager.hpp"
#include "psme/rest/constants/constants.hpp"
#include "psme/rest/validators/json_validator.hpp"
#include "psme/rest/validators/schemas/reset.hpp"
#include "psme/rest/endpoints/chassis/chassis_reset.hpp"
#include "psme/rest/server/error/error_factory.hpp"
#include "psme/rest/model/handlers/generic_handler_deps.hpp"
#include "psme/rest/model/handlers/generic_handler.hpp"

using namespace psme::rest;
using namespace psme::rest::constants;
using namespace psme::rest::validators;


endpoint::ChassisReset::ChassisReset(const std::string& path) : EndpointBase(path) {}


endpoint::ChassisReset::~ChassisReset() {}


void endpoint::ChassisReset::post(const server::Request& request, server::Response& response) {

    char command[256] = {0};
    char resultA[256] = {0};

    const auto& json = JsonValidator::validate_request_body<schema::ResetPostSchema>(request);
    agent_framework::model::attribute::Attributes attributes{};

    if (json.is_member(constants::Common::RESET_TYPE)) {
        const auto& reset_type = json[constants::Common::RESET_TYPE].as_string();
        attributes.set_value(agent_framework::model::literals::System::POWER_STATE, reset_type);

		using ResetType = agent_framework::model::enums::ResetType;

		const auto reset_type_e = ResetType::from_string(reset_type);

		switch (reset_type_e) {
			case agent_framework::model::enums::ResetType::None:
			case agent_framework::model::enums::ResetType::ForceOn:
			case agent_framework::model::enums::ResetType::Nmi:
			default:
				break;
			case agent_framework::model::enums::ResetType::On:
			case agent_framework::model::enums::ResetType::GracefulRestart:
				sprintf(command, "%s" ,"psme.sh set restart");	
				exec_shell(command, resultA);
				break;
			case agent_framework::model::enums::ResetType::PushPowerButton:
			case agent_framework::model::enums::ResetType::ForceRestart:
				sprintf(command, "%s" ,"psme.sh set force_restart");	
				exec_shell(command, resultA);
				break;
			case agent_framework::model::enums::ResetType::ForceOff:
				sprintf(command, "%s" ,"psme.sh set force_off");	
				exec_shell(command, resultA);
				break;
			case agent_framework::model::enums::ResetType::GracefulShutdown:
				sprintf(command, "%s" ,"psme.sh set shutdown");	
				exec_shell(command, resultA);
				break;
		}
    }

    if(!strncmp(resultA, "NOT support.", 12))
        response.set_status(server::status_5XX::NOT_IMPLEMENTED);
    else
        response.set_status(server::status_2XX::OK);
}

/*!
 * @section LICENSE
 *
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
 * @section DESCRIPTION
 * */

#include "agent-framework/module/network_components.hpp"
#include "agent-framework/command-ref/registry.hpp"
#include "agent-framework/command-ref/network_commands.hpp"

using namespace agent_framework::command_ref;
using namespace agent_framework::model;

namespace {
    void get_port_info(const GetEthernetSwitchPortInfo::Request& request,
                       GetEthernetSwitchPortInfo::Response& response) {
        auto& manager = agent_framework::module::NetworkComponents::
            get_instance()->get_port_manager();
        std::string uuid = request.get_uuid();
        EthernetSwitchPort port{};

        if (manager.entry_exists(uuid)) {
            port = manager.get_entry(uuid);
        }
        else {
            THROW(::agent_framework::exceptions::InvalidUuid, "network-agent",
                "Port not found, uuid = " + uuid);
        }
        response = port;
    }
}
 
REGISTER_COMMAND(GetEthernetSwitchPortInfo, ::get_port_info);

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
 *
 * @file get_drawer_power.cpp
 * @brief GetDrawerPower command handler for RMM.
 * */
#include <ipmb/command/get_drawer_power.hpp>

#include "agent-framework/module/chassis_components.hpp"
#include "agent-framework/module/common_components.hpp"

using namespace agent::chassis::ipmb::command;

using agent_framework::module::ChassisComponents;
using agent_framework::module::CommonComponents;

GetDrawerPower::~GetDrawerPower() {}

void GetDrawerPower::unpack(IpmiMessage& msg){
    log_debug(LOGUSR, "Unpacking GetDrawerPower message.");
    msg.set_to_request();
}

void GetDrawerPower::pack(IpmiMessage& msg){

    log_debug(LOGUSR, "Packing GetDrawerPower message.");

    DrawerPowerIpmbResponse response{};

    msg.set_to_response();

    make_response(response);

    // 1 byte bitmap present
    // + size of power data
    auto len = 1 + response.sled_count * sizeof(uint16_t);

    auto data = msg.get_data();
    data[OFFSET_CC] = uint8_t(CompletionCode::CC_OK);

    const auto src = reinterpret_cast<const uint8_t*>(&response);
    std::copy(src, src + len, data + OFFSET_DATA);

    // 1 byte completion code
    // + size of data
    msg.add_len(static_cast<std::uint16_t>(1 + len));

}

void GetDrawerPower::make_response(DrawerPowerIpmbResponse& response) {
    uint8_t sled_presence_bit_map = 0;
    uint8_t sled_presence_mask = 1;

    auto drawer_manager_keys = CommonComponents::get_instance()->
            get_module_manager().get_keys("");
    auto blade_manager_keys = CommonComponents::get_instance()->
            get_module_manager().get_keys(drawer_manager_keys.front());

    for (const auto& key: blade_manager_keys) {
        auto manager = CommonComponents::get_instance()->
                get_module_manager().get_entry(key);
        if (manager.get_presence()) {
            sled_presence_bit_map = uint8_t(sled_presence_bit_map | sled_presence_mask << (manager.get_slot() - 1));
            log_debug(LOGUSR, "Sled presence mask: " << std::to_string(static_cast<uint>(sled_presence_mask))
                      << " Sled presence bit map: " << std::to_string(static_cast<uint>(sled_presence_bit_map)));
            auto chassis_keys = CommonComponents::get_instance()->
                    get_chassis_manager().get_keys(manager.get_uuid());
            auto power_zone_keys = ChassisComponents::get_instance()->
                    get_power_zone_manager().get_keys(chassis_keys.front());

            auto power_zone = ChassisComponents::get_instance()->
                    get_power_zone_manager().get_entry_reference(power_zone_keys.front());

            response.sled_power[response.sled_count] = uint16_t(power_zone->get_power_input());

            response.sled_count++;
            sled_presence_mask = 1;
        }
    }

    response.sled_presence_bitmap = sled_presence_bit_map;
}

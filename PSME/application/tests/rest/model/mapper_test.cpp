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
 * */

#include "agent-framework/module/managers/generic_manager.hpp"
#include "psme/rest/model/handlers/database.hpp"

#include "psme/rest/constants/constants.hpp"
#include "psme/rest/utils/mapper.hpp"
#include "psme/rest/model/handlers/database.hpp"

#include "psme/rest/endpoints/path_builder.hpp"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

using namespace agent_framework;
using namespace testing;
using namespace psme::rest;
using namespace psme::rest::constants;

namespace psme {
namespace rest {
namespace model {

namespace handler {
class DatabaseTester {
public:
    static void drop_all() {
        Database::SPtr db = Database::create("*drop_all");
        AlwaysMatchKey key{};
        db->drop(key);
        db->remove();
    }
};
}

class MapperTest : public ::testing::Test {
public:
    ~MapperTest();

    void SetUp() {
        handler::DatabaseTester::drop_all();
    }
};

MapperTest::~MapperTest() { }

TEST_F(MapperTest, TestMapperGetParamFromComponent) {
    ASSERT_EQ(PathParam::ETHERNET_SWITCH_ID, psme::rest::model::Mapper::get_param_from_component("EthernetSwitches"));
    ASSERT_EQ(PathParam::SWITCH_PORT_ID, psme::rest::model::Mapper::get_param_from_component("Ports"));
    ASSERT_EQ(PathParam::SERVICE_ID, psme::rest::model::Mapper::get_param_from_component("Services"));
    ASSERT_EQ(PathParam::LOGICAL_DRIVE_ID, psme::rest::model::Mapper::get_param_from_component("LogicalDrives"));
}

TEST_F(MapperTest, TestMapperGetParamsPorts) {
    auto path = "/redfish/v1/EthernetSwitches/1/Ports/4";
    auto output = psme::rest::model::Mapper::get_params(path, constants::Routes::ETHERNET_SWITCH_PORT_PATH);

    ASSERT_EQ(output[PathParam::ETHERNET_SWITCH_ID], "1");
    ASSERT_EQ(output[PathParam::SWITCH_PORT_ID], "4");
}

TEST_F(MapperTest, TestMapperGetParamsTargets) {
    auto path = "/redfish/v1/Services/2/LogicalDrives/3";
    auto output = psme::rest::model::Mapper::get_params(path, constants::Routes::LOGICAL_DRIVE_PATH);

    ASSERT_EQ(output[PathParam::SERVICE_ID], "2");
    ASSERT_EQ(output[PathParam::LOGICAL_DRIVE_ID], "3");
}

TEST_F(MapperTest, TestNegativeMapperGetParams) {
    auto malformed_path = "/malformed/path/EthernetSwitches/1/Ports/4";
    auto wrong_id_path = "/redfish/v1/EthernetSwitches/NotId/Ports/4";
    auto unknown_resource_path = "/redfish/v1/UnknownResource/1/Ports/4";
    auto empty_path = "";

    ASSERT_ANY_THROW(psme::rest::model::Mapper::get_params(malformed_path,
                                                           constants::Routes::ETHERNET_SWITCH_PORT_PATH));
    ASSERT_ANY_THROW(psme::rest::model::Mapper::get_params(wrong_id_path,
                                                           constants::Routes::ETHERNET_SWITCH_PORT_PATH));
    ASSERT_ANY_THROW(psme::rest::model::Mapper::get_params(unknown_resource_path,
                                                           constants::Routes::ETHERNET_SWITCH_PORT_PATH));
    ASSERT_ANY_THROW(psme::rest::model::Mapper::get_params(empty_path,
                                                           constants::Routes::ETHERNET_SWITCH_PORT_PATH));
}


}
}
}

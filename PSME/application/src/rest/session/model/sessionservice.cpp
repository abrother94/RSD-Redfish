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


#include "psme/rest/session/model/sessionservice.hpp"
#include "psme/rest/constants/constants.hpp"
#include <json/json.hpp>
#include <stdexcept>
#include <iostream>

using namespace psme::rest::constants;

namespace psme {
namespace rest {
namespace session {
namespace model {

json::Value Sessionservice::to_json() const {
    json::Value json(json::Value::Type::OBJECT);

    return json;
}

void Sessionservice::from_json(const json::Value& json) {
    const auto& enable = json[SessionService::SERVICE_ENABLED].as_bool();
    const auto& timeout = json[SessionService::SERVICE_TIMEOUT].as_int();

    set_enabled(enable);
    set_timeout(timeout);  
 
    std::cout << "enable is " << enable << " timeout is " <<  timeout;

}



}
}
}
}

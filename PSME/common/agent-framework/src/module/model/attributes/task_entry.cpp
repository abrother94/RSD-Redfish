/*!
 * @brief TaskEntry class implementation
 *
 * @copyright
 * Copyright (c) 2016-2017 Intel Corporation
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
 * @file task_entry.cpp
 * */

#include "agent-framework/module/model/attributes/task_entry.hpp"
#include "agent-framework/module/constants/common.hpp"

#include <json/json.h>



using namespace agent_framework::model::attribute;
using namespace agent_framework::model;


TaskEntry::TaskEntry() { }


TaskEntry::~TaskEntry() { }


Json::Value TaskEntry::to_json() const {
    Json::Value entry;
    entry[literals::TaskEntry::TASK] = get_task();
    return entry;
}


TaskEntry TaskEntry::from_json(const Json::Value& json) {
    TaskEntry task_entry;
    task_entry.set_task(json[literals::TaskEntry::TASK].asString());
    return task_entry;
}

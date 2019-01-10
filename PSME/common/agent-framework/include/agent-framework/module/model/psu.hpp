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
 *
 * @brief Declaration of PSU resource class
 * @file psu.hpp
 * */

#pragma once
#include "agent-framework/module/model/attributes/model_attributes.hpp"
#include "agent-framework/module/model/resource.hpp"
#include "agent-framework/module/enum/common.hpp"

namespace agent_framework {
namespace model {

class Psu : public Resource {
public:

    explicit Psu(const std::string& parent_uuid = {}, enums::Component parent_type = enums::Component::None);
    ~Psu();

    Psu(const Psu&) = default;
    Psu& operator=(const Psu&) = default;
    Psu(Psu&&) = default;
    Psu& operator=(Psu&&) = default;

    /*!
     * @brief construct an object of class Psu from JSON
     *
     * @param json the Json::Value deserialized to object
     *
     * @return the newly constructed Psu object
     */
    static Psu from_json(const Json::Value& json);

    /*!
     * @brief transform the object to JSon
     *
     * @return the object serialized to Json::Value
     */
    Json::Value to_json() const;

    static enums::CollectionName get_collection_name() {
        return Psu::collection_name;
    }

    static enums::Component get_component() {
        return Psu::component;
    }

    /*!
     * @brief return slot of type uint32_t
     *
     * @return the slot value
     */
    OptionalField<uint32_t> get_slot() const {
        return m_slot;
    }

    /*!
     * @brief setter for slot attribute
     *
     * @param slot of type uint32_t
     */
    void set_slot(const OptionalField<uint32_t> slot) {
        m_slot = slot;
    }

    /*!
     * @brief return power_capacity of type double
     *
     * @return the power_capacity value
     */
    OptionalField<double> get_power_capacity() const {
        return m_power_capacity;
    }

    /*!
     * @brief setter for power_capacity attribute
     *
     * @param power_capacity of type double
     */
    void set_power_capacity(const OptionalField<double> power_capacity) {
        m_power_capacity = power_capacity;
    }

    /*!
     * @brief return power_input of type double
     *
     * @return the power_input value
     */
    OptionalField<double> get_power_input() const {
        return m_power_input;
    }

    /*!
     * @brief setter for power_input attribute
     *
     * @param power_input of type double
     */
    void set_power_input(const OptionalField<double> power_input) {
        m_power_input = power_input;
    }

    /*!
     * @brief return power_output of type double
     *
     * @return the power_output value
     */
    OptionalField<double> get_power_output() const {
        return m_power_output;
    }

    /*!
     * @brief setter for power_output attribute
     *
     * @param power_output of type double
     */
    void set_power_output(const OptionalField<double> power_output) {
        m_power_output = power_output;
    }

    /*!
	 * @brief return an object fru_info of class attribute::FruInfo
	 *
	 * @return the fru_info value
	 */
	const attribute::FruInfo& get_fru_info() const {
        return m_fru_info;
    }

    /*!
     * @brief setter for fru_info attribute
     *
     * @param fru_info of type attribute::FruInfo
     */
    void set_fru_info(const attribute::FruInfo& fru_info) {
        m_fru_info = fru_info;
    }

/*Nick Added Begin: */
   /*!
     * @brief setter for chassis attribute
     *
     * @param chassis of type std::string
     */
    void set_chassis(const OptionalField<std::string>& chassis) {
        m_chassis = chassis;
            log_debug(GET_LOGGER("PSU"), " set_chassis:" << m_chassis);
    }


    /*!
     * @brief return an object chassis of class std::string
     *
     * @return the chassis value
     */
    const OptionalField<std::string>& get_chassis() const {
               log_debug(GET_LOGGER("PSU"), " get_chassis:" << m_chassis);
        return m_chassis;
    }
	
    /*!
     * @brief setter for fan_id attribute
     *
     * @param fan_id of type uint32_t
     */
    void set_psu_id(const OptionalField<uint32_t> pz_id) {
        m_psu_id = pz_id;
    }

    /*!
     * @brief return pz_id of type std::uint32_t
     *
     * @return the pz_id value
     */
    OptionalField<std::uint32_t> get_psu_id() const {
        return m_psu_id;
    }

   /*!
     * @brief setter for status_health attribute
     *
     * @param status_health of type std::string
     */
    void set_status_health(const OptionalField<std::string>& status_health) {
        m_status_health = status_health;
    }

    /*!
     * @brief return an object status_health of class std::string
     *
     * @return the status_health value
     */
    const OptionalField<std::string>& get_status_health() const {
        return m_status_health;
    }

   /*!
     * @brief setter for status_state attribute
     *
     * @param status_state of type std::string
     */
    void set_status_state(const OptionalField<std::string>& status_state) {
        m_status_state = status_state;
    }

    /*!
     * @brief return an object status_state of class std::string
     *
     * @return the status_state value
     */
    const OptionalField<std::string>& get_status_state() const {
        return m_status_state;
    }

	
/*Nick Added End  : */

private:

    OptionalField<uint32_t> m_slot{0u};
    OptionalField<double> m_power_input{0.0};
    OptionalField<double> m_power_output{0.0};
    OptionalField<double> m_power_capacity{0.0};
    attribute::FruInfo m_fru_info{};
/*Nick Added Begin: */
    OptionalField<std::uint32_t> m_psu_id{0u}; 
    OptionalField<std::string> m_chassis{}; 
    OptionalField<std::string> m_status_health{};
    OptionalField<std::string> m_status_state{};	
/*Nick Added End  : */ 
    static const enums::CollectionName collection_name;
    static const enums::Component component;

};

}
}

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
 * @file discovery_manager.hpp
 *
 * @brief Initial discovery implementation.
 * */

#pragma once

#include "agent-framework/discovery/discovery.hpp"

#include <mutex>
#include <condition_variable>

namespace agent {
namespace network {
namespace discovery {

/*! @brief Implementation of initial discovery. */
class DiscoveryManager final : public agent_framework::discovery::Discovery {
public:

    /*! @brief Default constructor. */
    DiscoveryManager();

    /*! @brief Copy constructor */
    DiscoveryManager(const DiscoveryManager&) = default;

    /*! @brief Assignment operator */
    DiscoveryManager& operator=(const DiscoveryManager&) = default;

    /*! @brief Default destructor. */
    virtual ~DiscoveryManager();

    virtual void discovery(const std::string& uuid) override;

    /*! @brief Wait for discovery complete */
    void wait_for_complete();

private:
    std::mutex m_mutex{};
    std::condition_variable m_cv{};
};

}
}
}


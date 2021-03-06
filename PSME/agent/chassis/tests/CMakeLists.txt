# <license_header>
#
# Copyright (c) 2015-2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# </license_header>

if (NOT GTEST_FOUND)
    return()
endif()

add_subdirectory(loader)
add_subdirectory(session_test)

IF(${CUSEONLPLIB} STREQUAL "TRUE")
    add_subdirectory(onlp_test)
ENDIF()

IF("${CUSE_ACC_BAL_DISTLIB}" STREQUAL "TRUE" )
    add_subdirectory(acc_api_bal_dist_test)
ENDIF()

add_subdirectory(md5)
add_subdirectory(network_utils)
add_subdirectory(tree_stability)
add_subdirectory(ipmb)

add_custom_target(unittest_psme-chassis
                  make
)
add_custom_target(unittest_psme-chassis_run
                  ctest --output-on-failure
)

#!/usr/bin/env python
"""
 * @section LICENSE
 *
 * @copyright
 * Copyright (c) 2016 Intel Corporation
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
"""
from distutils.util import strtobool
from time import sleep

from cts_core.commons.api_caller import ApiCaller
from cts_core.commons.preconditions import Requirement, Preconditions
from cts_core.commons.services import RegisterService, ServiceTypes
from cts_core.discovery.api_explorer import ApiExplorer
from cts_core.metadata.metadata_constants import MetadataConstants2_1 as MetadataConstants
from cts_core.validation.hierarchy.hierarchy_validator import HierarchyValidator
from cts_core.validation.validation_status import ValidationStatus
from cts_framework.commons.enums import ReturnCodes
from cts_framework.helpers.python.cts_test_script import CtsTestScript
from cts_framework.helpers.python.test_script import TestScript


@RegisterService(ServiceTypes.PODM_2_1)
class HardwareCheckList(CtsTestScript):
    TIMEOUT = 600
    DESCRIPTION = """test script validating properties from hardware checklist"""
    CONFIGURATION_PARAMETERS = [
        TestScript.ConfigurationParameter(parameter_name="IsPsmePresent",
                                          parameter_description="Rack must have one or more Pooled System Management Engine software (PSME)",
                                          parameter_type=str, is_required=True, parameter_default_value=None),
        TestScript.ConfigurationParameter(parameter_name="PowerEfficiency",
                                          parameter_description="Power supply efficiency",
                                          parameter_type=float, is_required=True, parameter_default_value=None,
                                          min=0, max=100),
        TestScript.ConfigurationParameter(parameter_name="FanPositionNumberingConsistent",
                                          parameter_description="Is fan position numbering consistent left to right or top to bottom",
                                          parameter_type=str, is_required=True, parameter_default_value=None),
        TestScript.ConfigurationParameter(parameter_name="PowerSupplyPositionNumberingConsistent",
                                          parameter_description="Is power supply numbering position consistent left to right or top to bottom",
                                          parameter_type=str, is_required=True, parameter_default_value=None),
        TestScript.ConfigurationParameter(parameter_name="IsRMMNetworkPrivateManagement",
                                          parameter_description="Yes/No if RMM is in private management network",
                                          parameter_type=str, is_required=True, parameter_default_value=None),
        TestScript.ConfigurationParameter(parameter_name="AreManagementAndProductionNetworksSeparated",
                                          parameter_description="Yes/No if management and production network are separated",
                                          parameter_type=str, is_required=True, parameter_default_value=None),
        TestScript.ConfigurationParameter(parameter_name="AreComputeBladesServiceableIndependently",
                                          parameter_description="Yes/No. Compute blades must support modular CPU and memory that can be serviced " \
                                                                "or upgraded independent of shared resources "\
                                                                "(shared power, shared cooling, shared network, shared storage)",
                                          parameter_type=str, is_required=True, parameter_default_value=None),
    ]

    def run(self):
        print "TEST_CASE::API crawling"
        api_explorer = ApiExplorer(self.metadata_container, self.configuration)

        discovery_container, status = api_explorer.discover(MetadataConstants.SERVICE_ROOT_URI,
                                                            MetadataConstants.SERVICE_ROOT)
        print "STATUS::{status}".format(status=status)

        print "TEST_CASE::Checking for mandatory entities"
        requirements = [
            Requirement(MetadataConstants.SERVICE_ROOT, min=1, max=1)
        ]
        preconditions = Preconditions(self.metadata_container, requirements)
        self.set_validation_status(preconditions.validate(discovery_container))

        validation_functions = [self.at_least_one_compute_module_in_pod,
                                self.at_least_one_ethernet_switch_in_the_pod,
                                self.ethernet_based_fabric_for_network_connectivity,
                                self.secure_communication_channel,
                                self.node_reset_support, self.manual_tests,
                                self.validate_all_or_none_chassis_have_location,
                                self.validate_path_using_contains_property,
                                self.power_monitoring_support]

        for validation_function in validation_functions:
            try:
                validation_function(discovery_container)
            except Exception as err:
                print "ERROR::Exception %s" % err
                self.set_validation_status(ValidationStatus.FAILED)

        print "SCREEN::Overall status: %s" % self.validation_status

    def set_validation_status(self, status):
        print "STATUS::%s" % status
        if hasattr(self, "validation_status"):
            self.validation_status = ValidationStatus.join_statuses(self.validation_status, status)
        else:
            self.validation_status = status

    def at_least_one_compute_module_in_pod(self, discovery_container):
        """
        Test is checking for rsa compute module presence
        :type discovery_container: cts_core.discovery.discovery_container.DiscoveryContainer
        :type self.metadata_container: cts_core.metadata.self.metadata_container.MetadataContainer
        """
        print "TEST_CASE::At least one RSA compute module in POD"

        for resource_link, resource in discovery_container.iteritems():
            if self.metadata_container.entities[MetadataConstants.COMPUTER_SYSTEM].compare_entities(resource.odata_type):
                try:
                    processor_count = resource.body["ProcessorSummary"]["Count"]
                    memory_size = resource.body["MemorySummary"]["TotalSystemMemoryGiB"]
                    if int(processor_count) > 0 and memory_size is not None and int(memory_size) > 0:
                       print "DEBUG::Found compute module with processors and memory - %s" % (resource_link)
                       self.set_validation_status(ValidationStatus.PASSED)
                       return
                except KeyError:
                    pass

        print "ERROR::Computer System with memory and processors not found"
        self.set_validation_status(ValidationStatus.FAILED)

    def at_least_one_ethernet_switch_in_the_pod(self, discovery_container):
        """
        Test is checking for ethernet switch presence
        :type discovery_container: cts_core.discovery.discovery_container.DiscoveryContainer
        :type self.metadata_container: cts_core.metadata.self.metadata_container.MetadataContainer
        """
        print "TEST_CASE::At least one Ethernet switch in the pod"

        for resource_link, resource in discovery_container.iteritems():
            if self.metadata_container.entities[MetadataConstants.ETHERNET_SWITCH].compare_entities(resource.odata_type):
                print "DEBUG::found entity of type %s in %s" % (MetadataConstants.ETHERNET_SWITCH, resource_link)
                self.set_validation_status(ValidationStatus.PASSED)
                return

        print "ERROR::Ethernet switch not found"
        self.set_validation_status(ValidationStatus.FAILED)

    def ethernet_based_fabric_for_network_connectivity(self, discovery_container):
        """
        Test is checking if ethernet based fabric is used for network connectivity
        :type discovery_container: cts_core.discovery.discovery_container.DiscoveryContainer
        :type self.metadata_container: cts_core.metadata.self.metadata_container.MetadataContainer
        """
        print "TEST_CASE::Ethernet-based fabric for network connectivity"

        for resource_link, resource in discovery_container.iteritems():
            if self.metadata_container.entities[MetadataConstants.ETHERNET_SWITCH].compare_entities(resource.odata_type):
                print "DEBUG::found Ethernet-based fabric in %s" % resource_link
                self.set_validation_status(ValidationStatus.PASSED)
                return

        print "ERROR::Ethernet-based fabric not found"
        self.set_validation_status(ValidationStatus.FAILED)

    def secure_communication_channel(self, discovery_container):
        """
        Test is checking if communication to POD manager is secure
        :type discovery_container: cts_core.discovery.discovery_container.DiscoveryContainer
        :type self.metadata_container: cts_core.metadata.self.metadata_container.MetadataContainer
        """
        print "TEST_CASE::Secure Communication Channel"
        if strtobool(self.configuration.UseSSL):
            if discovery_container.items():
                self.set_validation_status(ValidationStatus.PASSED)
            else:
                print "ERROR::secure channel enabled, but unable to retrieve API content"
                self.set_validation_status(ValidationStatus.FAILED)
        else:
            print "ERROR::Secure channel is disabled"
            self.set_validation_status(ValidationStatus.FAILED)

    def node_reset_support(self, discovery_container):
        """
        Test is checking if client is able to perform compute blade reset
        :type discovery_container: cts_core.discovery.discovery_container.DiscoveryContainer
        :type self.metadata_container: cts_core.metadata.self.metadata_container.MetadataContainer
        """
        print "TEST_CASE::Node reset support"

        test_timeout = 30

        computer_systems = {}
        api_caller = ApiCaller(self.configuration)

        for resource_link, resource in discovery_container.iteritems():
            if self.metadata_container.entities[MetadataConstants.COMPUTER_SYSTEM_1_0_0].compare_entities(resource.odata_type):
                print "MESSAGE::Found Computer System in %s" % resource_link
                computer_systems[resource_link] = resource

        tested_computer_system, tested_computer_system_state = None, None

        for system in computer_systems.keys():
            try:
                status = computer_systems[system].body["Status"]
                memory_gib = computer_systems[system].body["MemorySummary"]["TotalSystemMemoryGiB"]
                if status["Health"] == "OK" and status["State"] == "Enabled" and memory_gib is not None:
                    tested_computer_system = system
                    tested_computer_system_state = computer_systems[system].body["PowerState"]
                    break
            except:
                continue

        if not tested_computer_system:
            print "ERROR::No Computer System suitable for test found (must be enabled and healthy)"
            self.set_validation_status(ValidationStatus.BLOCKED)
            return

        # mapping accepted states with commands to send
        computer_system_reset_commands = {"Off": "On", "On": "ForceOff"}

        if tested_computer_system_state not in computer_system_reset_commands.keys():
            print "ERROR::Computer System's state neither \"Off\" nor \"On\""
            self.set_validation_status(ValidationStatus.FAILED)
            return
        else:
            # by substracting Current System state from {"On", "Off"} set we get the state we expect the Computer System
            # to be in after Reset command
            expected_computer_system_state = list(set(computer_system_reset_commands.keys()) -
                                                     {tested_computer_system_state})[0]
            print "MESSAGE::Will try to Power %s Computer System %s " % (expected_computer_system_state,
                                                                        tested_computer_system)

        status, status_code, response_body, _ = api_caller.post_resource("%s/Actions/ComputerSystem.Reset" %
            tested_computer_system, payload={"ResetType": "%s" % computer_system_reset_commands[tested_computer_system_state]},
            acceptable_return_codes = [ReturnCodes.NO_CONTENT])

        if status:
            print "MESSAGE::Reset action accepted by server"
        else:
            print "ERROR::Incorrect status code %s" % status_code
            print "ERROR::Response body:\n%s" % response_body
            self.set_validation_status(ValidationStatus.FAILED)

        print ("MESSAGE::Waiting up to %ss for the Computer System to change its state to %s" %
                                            (test_timeout, expected_computer_system_state))

        test_duration = 0

        while test_duration < test_timeout:
            sleep(1)
            test_duration += 1
            status, status_code, response_body, _ = api_caller.get_resource(tested_computer_system)

            if not status:
                print "ERROR::Could not get %s info from the server" % tested_computer_system
                print "ERROR::Incorrect status code %s" % status_code
                print "ERROR::Response body:\n%s" % response_body
                self.set_validation_status(ValidationStatus.FAILED)
                return

            if response_body["PowerState"] == expected_computer_system_state:
                print "Message::Computer System has successfully change its state"
                self.set_validation_status(ValidationStatus.PASSED)
                return

        print "ERROR::Computer System did not change its state in time"
        self.set_validation_status(ValidationStatus.FAILED)
        return


    def manual_tests(self, discovery_container):

        """
        Manual tests from hw checklist
        :type discovery_container: cts_core.discovery.discovery_container.DiscoveryContainer
        :type self.metadata_container: cts_core.metadata.self.metadata_container.MetadataContainer
        """
        print "TEST_CASE::Rack must have one or more Pooled System Management Engine software (PSME)"
        if strtobool(self.configuration.IsPsmePresent):
            self.set_validation_status(ValidationStatus.PASSED)
        else:
            print "ERROR::Rack must have one or more Pooled System Management Engine software (PSME)"
            self.set_validation_status(ValidationStatus.FAILED)
        print "TEST_CASE::Shared or high efficiency power supply"
        if self.configuration.PowerEfficiency > 90:
            self.set_validation_status(ValidationStatus.PASSED)
        else:
            print ("ERROR::shared or high efficiency power supply not present, declared efficiency {declared_efficiency}% " +
                   "must be > 90%").format(declared_efficiency=self.configuration.PowerEfficiency)
            self.set_validation_status(ValidationStatus.FAILED)

        print "TEST_CASE::Fan position numbering consistent"
        if strtobool(self.configuration.FanPositionNumberingConsistent):
            self.set_validation_status(ValidationStatus.PASSED)
        else:
            print "ERROR::fan position numbering is not consistent"
            self.set_validation_status(ValidationStatus.FAILED)

        print "TEST_CASE::Power supply position numbering consistent"
        if strtobool(self.configuration.PowerSupplyPositionNumberingConsistent):
            self.set_validation_status(ValidationStatus.PASSED)
        else:
            print "ERROR::Power supply position numbering is not consistent"
            self.set_validation_status(ValidationStatus.FAILED)

        print "TEST_CASE::if have discrete Rack Management Module (RMM) present, must be private management network"
        if strtobool(self.configuration.IsRMMNetworkPrivateManagement):
            self.set_validation_status(ValidationStatus.PASSED)
        else:
            print "ERROR::Power supply position numbering is not consistent"
            self.set_validation_status(ValidationStatus.FAILED)

        print "TEST_CASE::Management network and production network separation"
        if strtobool(self.configuration.AreManagementAndProductionNetworksSeparated):
            self.set_validation_status(ValidationStatus.PASSED)
        else:
            print "ERROR::Management network and production network are not separated"
            self.set_validation_status(ValidationStatus.FAILED)

        print "TEST_CASE::Compute blade serviceability independence"
        if strtobool(self.configuration.AreComputeBladesServiceableIndependently):
            self.set_validation_status(ValidationStatus.PASSED)
        else:
            print "ERROR::Compute blades are not serviceable independently"
            self.set_validation_status(ValidationStatus.FAILED)

    def validate_all_or_none_chassis_have_location(self, discovery_container):
        print "TEST_CASE::Validate that all or none chassis has Location"
        validator = HierarchyValidator(discovery_container, self.metadata_container, MetadataConstants)
        result = validator.validate_all_or_none_chassis_have_location()
        if result in [ValidationStatus.PASSED, ValidationStatus.PASSED_WITH_WARNINGS]:
            self.set_validation_status(ValidationStatus.PASSED)
        else:
            self.set_validation_status(ValidationStatus.FAILED)

    def validate_path_using_contains_property(self, discovery_container):
        print "TEST_CASE::Validate chassis hierarchy (including 'Unique drawer ID within the rack', " \
              "'Unique module ID within the drawer')"
        validator = HierarchyValidator(discovery_container, self.metadata_container, MetadataConstants)
        result = validator.validate_path_using_contains_property()
        if result in [ValidationStatus.PASSED, ValidationStatus.PASSED_WITH_WARNINGS]:
            self.set_validation_status(ValidationStatus.PASSED)
        else:
            self.set_validation_status(ValidationStatus.FAILED)

    def power_monitoring_support(self, discovery_container):
        """
        Test is basing on fact, that without PSME there's no healthy drawer on PODm API.
        :type discovery_container: cts_core.discovery.discovery_container.DiscoveryContainer
        :type self.metadata_container: cts_core.metadata.self.metadata_container.MetadataContainer
        """
        print "TEST_CASE::Power monitoring support"

        all_chassis = [r for r in discovery_container.iter_all(MetadataConstants.CHASSIS, self.metadata_container)
                        if r.body["ChassisType"] == "Rack"]

        if len(all_chassis) == 0:
            print "ERROR::Rack chassis not found"
            self.set_validation_status(ValidationStatus.FAILED)
            return


        overall_error = False
        overall_result = True

        for chassis in all_chassis:
            error = False
            result = True
            print "MESSAGE::Checking chassis %s" % chassis.odata_id
            error, monitoring_supported_via_power_property = self._check_power(chassis, discovery_container, error)
            error, monitoring_supported_via_power_zones = self._check_power_zones(chassis, discovery_container, error)

            result = monitoring_supported_via_power_property or monitoring_supported_via_power_zones
            if result and not error:
                print "MESSAGE::Chassis %s is OK" % chassis.odata_id
            else:
                print "ERROR::Chassis %s does not have power monitoring" % chassis.odata_id


            overall_error = overall_error or error
            overall_result = overall_result and result

        if overall_result and not overall_error:
            self.set_validation_status(ValidationStatus.PASSED)
            return
        else:
            self.set_validation_status(ValidationStatus.FAILED)

    def _check_power(self, chassis, discovery_container, error):
        """Check if power monitoring is possible via 'Power' property """
        print "MESSAGE::Checking Power property"
        power_control_ok = False

        try:
            power_id = chassis.body["Power"]["@odata.id"]

            power = discovery_container.get(power_id, None)
            if power is None:
                print "ERROR::Unknown Power: %s" % power_id
                error = True
            else:
                power_controls = [m.get("@odata.id", None) for m in power.body.get("PowerControl", list())]
                for power_control_id in power_controls:
                    if power_control_id is None:
                        continue
                    power_control = discovery_container.get(power_control_id, None)
                    if power_control is None:
                        print "ERROR::Unknown PowerControl: %s" % power_control_id
                        error = True
                    else:
                        try:
                            power_consumed_watts = float(power_control.body['PowerConsumedWatts'])
                            if power_consumed_watts > 0:
                                print "MESSAGE::Found PowerConsumedWatts > 0 in %s.Power [...]" % chassis.odata_id
                                power_control_ok = True # this is it!  can monitor power consumption
                            else:
                                print "WARNING::power_consumed_watts = %f. Looking for value > 0" % power_consumed_watts
                        except KeyError:
                            print "MESSAGE::PowerConsumedWatts not found in PowerControl: %s" % power_control_id
        except KeyError:
            print "MESSAGE::Power property not found in chassis %s" % chassis.odata_id

        return error, power_control_ok

    def _check_power_zones(self, chassis, discovery_container, error):
        """Check if power monitoring is possible via 'PowerZones' property """
        print "MESSAGE::Checking power zones"
        power_control_ok = False

        try:
            power_zones_id = chassis.body["PowerZones"]["@odata.id"]
            power_zones = discovery_container.get(power_zones_id, None)

            if power_zones is None:
                print "ERROR::Unknown PowerZones: %s" % power_zones_id
                error = True
            else:
                member_ids = [m.get("@odata.id", None) for m in power_zones.body.get("Members", list())]
                for power_zone_id in member_ids:
                    if power_zone_id is None:
                        continue
                    power_zone = discovery_container.get(power_zone_id, None)
                    if power_zone is None:
                        print "ERROR::Unknown PowerZone: %s" % power_zone_id
                        error = True
                    else:
                        try:
                            power_consumed_watts = float(power_zone.body['PowerConsumedWatts'])
                            if power_consumed_watts > 0: # this is it!  can monitor power consumption
                                print "MESSAGE::Found PowerConsumedWatts > 0 in %s.PowerZones [...]" % chassis.odata_id
                                power_control_ok = True
                            else:
                                print "WARNING::power_consumed_watts = %f. Looking for value > 0" % power_consumed_watts
                        except KeyError:
                            print "MESSAGE::PowerConsumedWatts not found in PowerZone: %s" % power_zone_id

        except KeyError:
            print "MESSAGE::PowerZones attribute not found in chassis %s" % (chassis.odata_id)

        return error, power_control_ok


if __name__ == '__main__':
    HardwareCheckList.service_cli()

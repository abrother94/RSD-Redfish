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
 * @file certificate.cpp
 * @brief Certificate
 * */
#include "agent-framework/module/network_components.hpp"
#include "agent-framework/module/chassis_components.hpp"
#include "agent-framework/module/common_components.hpp"
#include "agent-framework/command-ref/network_commands.hpp"
#include "agent-framework/eventing/event_data.hpp"
#include "agent-framework/eventing/events_queue.hpp"
#include <ipmb/watcher/thermal_sensor_task.hpp>
#include <ipmb/command/thermal_sensor_response.hpp>
#include <ipmb/gpio.hpp>
#include <ipmb/service.hpp>

#include <ipmi/command/generic/get_device_id.hpp>
#include <ipmi/command/generic/get_sensor_reading.hpp>
#include <ipmi/command/generic/get_sensor_reading_factors.hpp>
#include <ipmi/command/sdv/get_fan_pwm.hpp>
#include <ipmi/manager/ipmitool/management_controller.hpp>

#include <acc_net_helper/acc_net_helper.hpp>
using namespace acc_net_helper;

#ifdef ONLP
#include "acc_onlp_helper/acc_onlp_helper.hpp"
using namespace acc_onlp_helper;
#endif

using namespace std;
using namespace agent_framework::model;
using namespace agent_framework::module;
using namespace agent::chassis;
using namespace agent::chassis::ipmb;
using namespace agent::chassis::ipmb::watcher;
using namespace ipmi;
using namespace ipmi::command;

using namespace agent_framework::command_ref;
//using namespace agent::network;

using agent_framework::module::ChassisComponents;
using agent_framework::module::CommonComponents;
using agent_framework::module::NetworkComponents;


OnlpSensorTask::~OnlpSensorTask() {}

/*! Drawer onlp sensor processing*/
class GetOnlpInfo {
public:
    /*!
     * Executes Drawer thermal sensor processing
     * @param[in] manager_keys Blades' manager keys
     */
    void execute() {
        get_onlp_info();
    }
	void exec_shell(const char* cmd, char * result_a);

private:

    ThermalSensorIpmbResponse m_response{};
    void get_onlp_info();
};

void OnlpSensorTask::execute() {
    try {
        GetOnlpInfo ps{};
        ps.execute();
    }
    catch (const std::exception& e) {
        log_debug(LOGUSR, "GetOnlpInfo - exception : " << e.what());
    }
}


void GetOnlpInfo::exec_shell(const char* cmd, char * result_a){
	char buffer[128];
	std::string result = "";
	FILE* pipe = popen(cmd, "r");
	if (!pipe) throw std::runtime_error("popen() failed!");
	try {
	        while (!feof(pipe)) {
	                if (fgets(buffer, 128, pipe) != NULL)
	                        result += buffer;
	        }
	} catch (...) {
	        pclose(pipe);
	        throw;
	}
	pclose(pipe);
       sprintf(result_a,"%s", result.c_str());
	
	return;
	}


#ifndef ONLP
static unsigned int pre_fan_presence= 0;
static unsigned int pre_psu_presence= 0;

static signed int  UPPER_CPU_THRESHOLD_NON_CRITICAL=0;
static signed int  UPPER_CPU_THRESHOLD_CRITICAL=0;
static signed int  UPPER_CPU_THRESHOLD_FATAL=0;

static signed int  UPPER_SYS_THRESHOLD_NON_CRITICAL=0;
static signed int  UPPER_SYS_THRESHOLD_CRITICAL=0;
static signed int  UPPER_SYS_THRESHOLD_FATAL=0;
#define ZERO 0
#endif



void GetOnlpInfo::get_onlp_info() {


#ifdef ONLP
    auto& sonlp = Switch::Switch::get_instance();

    /*Get/Set  FAN info.*/
    sonlp.get_fan_info();
    unsigned int fan_num = sonlp.get_fan_num();

    unsigned int fanid=1;

    for(fanid = 1; fanid <=fan_num ; fanid++)
    {       
        auto &fan_manager = agent_framework::module::ChassisComponents::get_instance()->get_fan_manager();
        auto fan_uuids = fan_manager.get_keys();

        for (const auto& fan_uuid : fan_uuids) 
        {
            auto fan_ = fan_manager.get_entry_reference(fan_uuid);  //Get Fan object by fan_uuid//

            if (fan_->get_fan_id() == fanid) 
            {
                int current_rpm = sonlp.get_fan_info_by_(fanid, Switch::Fan_Content::RPM);
                fan_->set_current_speed(current_rpm);

                int current_fan_type = sonlp.get_fan_info_by_(fanid, Switch::Fan_Content::Type);
                fan_->set_fan_type(current_fan_type);	

                std::string  current_health = sonlp.get_fan_info_by_(fanid, "Status_Health");
                fan_->set_status_health(current_health);						

                std::string  current_state = sonlp.get_fan_info_by_(fanid, "Status_State");
                fan_->set_status_state(current_state);
            }
        } 
    }

    sonlp.update_fan_present_event();		

    /*Get/Set  PSU info.*/
    sonlp.get_psu_info();

    unsigned int psu_num =  sonlp.get_psu_num();

    unsigned int psuid=1;

    auto &psu_manager = agent_framework::module::ChassisComponents::get_instance()->get_psu_manager();

    auto psu_uuids = psu_manager.get_keys();

    for(psuid = 1; psuid <=psu_num ; psuid++)
    {  
        for (const auto& psu_uuid : psu_uuids) 
        {
            auto psu_ = psu_manager.get_entry_reference(psu_uuid);  //Get Psu object by psu_uuid//

            if (psu_->get_psu_id() == psuid) 
            {
                int current_pout = sonlp.get_psu_info_by_(psuid , Switch::Psu_Content::Pout);	
                psu_->set_power_output(current_pout);

                std::string  current_health = sonlp.get_psu_info_by_(psuid, "Status_Health");
                psu_->set_status_health(current_health);						

                std::string  current_state = sonlp.get_psu_info_by_(psuid, "Status_State");
                psu_->set_status_state(current_state);
            }		 
        }
    }

    sonlp.update_psu_present_event();		

    /*Get/Set  Thernal info.*/		
    sonlp.get_thermal_info();

    unsigned int thermal_num =  sonlp.get_thermal_num();
    unsigned int thermalid=1;


    auto &tz_manager = agent_framework::module::ChassisComponents::get_instance()->get_thermal_zone_manager();

    auto tz_uuids = tz_manager.get_keys();

    for(thermalid = 1; thermalid <=thermal_num ; thermalid++)
    { 	 
        for (const auto& tz_uuid : tz_uuids) 
        {
            auto tz_ = tz_manager.get_entry_reference(tz_uuid);  //Get Psu object by psu_uuid//
            if (tz_->get_tz_id() == thermalid) 
            { 
                int current_temp = sonlp.get_thermal_info_by_(thermalid , Switch::Thermal_Content::Current_Temperature);	
                tz_->set_temperature(current_temp);

                int current_thermal_type = sonlp.get_thermal_info_by_(thermalid, Switch::Thermal_Content::Thermal_Type);
                tz_->set_thermal_type(current_thermal_type);	

                std::string  current_health = sonlp.get_thermal_info_by_(thermalid, "Status_Health");
                tz_->set_status_health(current_health);						

                std::string  current_state = sonlp.get_thermal_info_by_(thermalid, "Status_State");
                tz_->set_status_state(current_state);

                int warning_tmp = sonlp.get_thermal_info_by_(thermalid , Switch::Thermal_Content::Warning);	
                tz_->set_warning_temp(warning_tmp);

                int error_tmp = sonlp.get_thermal_info_by_(thermalid , Switch::Thermal_Content::Error);	
                tz_->set_error_temp(error_tmp);		

                int shutdown_tmp = sonlp.get_thermal_info_by_(thermalid , Switch::Thermal_Content::Shutdown);	
                tz_->set_shutdown_temp(shutdown_tmp);						

            }
        }
    }
    sonlp.update_thermal_present_event();		


    /*Get/Set  Port info.*/			
    sonlp.get_port_info();

    unsigned int port_num =  sonlp.get_port_num();
    unsigned int portid=1;

    auto network_components = agent_framework::module::NetworkComponents::get_instance();
    auto &port_manager = network_components->get_instance()->get_port_manager();
    auto port_uuids = port_manager.get_keys();

    for(portid = 1; portid <=port_num ; portid++)
    { 	     
        for (const auto& port_uuid : port_uuids) 
        {
            auto port_ = port_manager.get_entry_reference(port_uuid);  //Get Port object by psu_uuid//

            if (port_->get_port_id() == portid) 
            { 
                int current_present = sonlp.get_port_info_by_(portid , Switch::Port_Content::Port_Present);

                if(current_present)
               {
                   port_->set_status(attribute::Status(
                   agent_framework::model::enums::State::Enabled,
                   agent_framework::model::enums::Health::OK));               
               }
               else
               {
                   port_->set_status(attribute::Status(
                   agent_framework::model::enums::State::Absent,
                   agent_framework::model::enums::Health::OK));               
               }
			   
               //Collect  trans info			   
               json::Value r(json::Value::Type::OBJECT);	
               attribute::TransInfo tTransInfo;			   
			   
               r = sonlp.get_port_trans_info_by_(portid);

               tTransInfo.set_spf_vendor_name(r["SFP Vendor Name"]);
               tTransInfo.set_part_number(r["Part Number"]);		   
               tTransInfo.set_serial_number(r["Serial Number"]);		   
               tTransInfo.set_manufacture_date(r["Manufacture Date"]);
                
               tTransInfo.set_temp_reading(r["Temperature"]["Reading"]);
               tTransInfo.set_temp_upper_th_fatal(r["Temperature"]["UpperThresholdFatal"]);		   
               tTransInfo.set_temp_upper_th_critical(r["Temperature"]["UpperThresholdCritical"]);
               tTransInfo.set_temp_lower_th_critical(r["Temperature"]["LowerThresholdCritical"]);
               tTransInfo.set_temp_lower_th_fatal(r["Temperature"]["LowerThresholdFatal"]);
               tTransInfo.set_temp_status_state(r["Temperature"]["Status"]["State"]);
               tTransInfo.set_temp_status_health(r["Temperature"]["Status"]["Health"]);
			   
               tTransInfo.set_voltage_reading(r["Voltage"]["Reading"]);
               tTransInfo.set_voltage_upper_th_fatal(r["Voltage"]["UpperThresholdFatal"]);		   
               tTransInfo.set_voltage_upper_th_critical(r["Voltage"]["UpperThresholdCritical"]);
               tTransInfo.set_voltage_lower_th_critical(r["Voltage"]["LowerThresholdCritical"]);
               tTransInfo.set_voltage_lower_th_fatal(r["Voltage"]["LowerThresholdFatal"]);
               tTransInfo.set_voltage_status_state(r["Voltage"]["Status"]["State"]);
               tTransInfo.set_voltage_status_health(r["Voltage"]["Status"]["Health"]);

               tTransInfo.set_bias_current_reading(r["BiasCurrent"]["Reading"]);
               tTransInfo.set_bias_current_upper_th_fatal(r["BiasCurrent"]["UpperThresholdFatal"]);		   
               tTransInfo.set_bias_current_upper_th_critical(r["BiasCurrent"]["UpperThresholdCritical"]);
               tTransInfo.set_bias_current_lower_th_critical(r["BiasCurrent"]["LowerThresholdCritical"]);
               tTransInfo.set_bias_current_lower_th_fatal(r["BiasCurrent"]["LowerThresholdFatal"]);
               tTransInfo.set_bias_current_status_state(r["BiasCurrent"]["Status"]["State"]);
               tTransInfo.set_bias_current_status_health(r["BiasCurrent"]["Status"]["Health"]);			   

               tTransInfo.set_tx_power_reading(r["TxPower"]["Reading"]);
               tTransInfo.set_tx_power_upper_th_fatal(r["TxPower"]["UpperThresholdFatal"]);		   
               tTransInfo.set_tx_power_upper_th_critical(r["TxPower"]["UpperThresholdCritical"]);
               tTransInfo.set_tx_power_lower_th_critical(r["TxPower"]["LowerThresholdCritical"]);
               tTransInfo.set_tx_power_lower_th_fatal(r["TxPower"]["LowerThresholdFatal"]);
               tTransInfo.set_tx_power_status_state(r["TxPower"]["Status"]["State"]);
               tTransInfo.set_tx_power_status_health(r["TxPower"]["Status"]["Health"]);			   
			   
               tTransInfo.set_rx_power_reading(r["RxPower"]["Reading"]);
               tTransInfo.set_rx_power_upper_th_fatal(r["RxPower"]["UpperThresholdFatal"]);		   
               tTransInfo.set_rx_power_upper_th_critical(r["RxPower"]["UpperThresholdCritical"]);
               tTransInfo.set_rx_power_lower_th_critical(r["RxPower"]["LowerThresholdCritical"]);
               tTransInfo.set_rx_power_lower_th_fatal(r["RxPower"]["LowerThresholdFatal"]);
               tTransInfo.set_rx_power_status_state(r["RxPower"]["Status"]["State"]);
               tTransInfo.set_rx_power_status_health(r["RxPower"]["Status"]["Health"]);			   
			   
               port_->set_trans_info(tTransInfo);			   
               
            }
        }
    }
	
    sonlp.update_port_present_event();		

    /*Send all events */
    std::vector<std::string> tmp_e_a =  sonlp.get_Event_Resouce_Add();
	
    for(unsigned int i = 0; i < tmp_e_a.size(); i++)
    {
        std::string t_es = tmp_e_a[i];
        agent_framework::eventing::EventData edat;
        edat.set_notification(::agent_framework::eventing::Notification::ResourceAdded);
        edat.set_event_content(t_es); 		
        agent_framework::eventing::EventsQueue::get_instance()->push_back(edat);
    }

    std::vector<std::string> tmp_e_r =  sonlp.get_Event_Resouce_Remove();
	
    for(unsigned int i = 0; i < tmp_e_r.size(); i++)
    {
        std::string t_er = tmp_e_r[i];
        agent_framework::eventing::EventData edat;
        edat.set_notification(::agent_framework::eventing::Notification::ResourceRemoved);
        edat.set_event_content(t_er); 			 
        agent_framework::eventing::EventsQueue::get_instance()->push_back(edat);
    }

    std::vector<std::string> tmp_e_al =  sonlp.get_Event_Resouce_Alert();
	
    for(unsigned int i = 0; i < tmp_e_al.size(); i++)
    {
        std::string t_ea = tmp_e_al[i];
        agent_framework::eventing::EventData edat;
        edat.set_notification(::agent_framework::eventing::Notification::Alert);
        edat.set_event_content(t_ea); 			 	 
        agent_framework::eventing::EventsQueue::get_instance()->push_back(edat);
    }
    sonlp.clean_Event_Rresouce_Event(); //Reset event //

	
    //For Intel_RSD TOR Switch 5812 //
    // Clean previous data //
#ifndef COMCAST	
    memset(resultA, 0x0, sizeof(resultA));	
    sprintf(lldpcmd,"/usr/local/sbin/lldpcli unconfigure lldp custom-tlv");
    exec_shell(lldpcmd, resultA);

    memset(resultA, 0x0, sizeof(resultA));	
    exec_shell("psme.sh get psu_power_out_sum", resultA);
    if(strlen(resultA) !=0 )
    {  	   
        sprintf(lldpcmd,"/usr/local/sbin/lldpcli configure lldp custom-tlv add oui 00,00,e8 subtype 1 oui-info 4d,4f,44,50,57,52,3a,%s", resultA);
        exec_shell(lldpcmd, resultA);
    }
#endif

#else


    uint32_t i = 0;
    char resultA[128];
    char lldpcmd[128];
    int tmp1[8] = {0};
    int fan_presence= 0;
    int psu_presence= 0;	
    int id=0;

    if(UPPER_SYS_THRESHOLD_NON_CRITICAL == 0)
    {
        sprintf(lldpcmd, "psme.sh get upper_sys_th_thermal_temp");
        memset(resultA,0x0, sizeof(resultA));
        exec_shell(lldpcmd, resultA);

        if(strlen(resultA) != 0)
        {  
            int tmp2[3] = {0};
            sscanf(resultA, "%d %d %d" ,  &tmp2[0] , &tmp2[1], &tmp2[2]);         
            UPPER_SYS_THRESHOLD_NON_CRITICAL = (tmp2[0]);
            UPPER_SYS_THRESHOLD_CRITICAL = (tmp2[1]);
            UPPER_SYS_THRESHOLD_FATAL = (tmp2[2]);;
        }
    }		

    if(UPPER_CPU_THRESHOLD_NON_CRITICAL == 0)
    {
        sprintf(lldpcmd, "psme.sh get upper_cpu_th_thermal_temp");
        memset(resultA,0x0, sizeof(resultA));
        exec_shell(lldpcmd, resultA);

        if(strlen(resultA) != 0)
        {  
            int tmp2[3] = {0};
            sscanf(resultA, "%d %d %d" ,  &tmp2[0] , &tmp2[1], &tmp2[2]);         
            UPPER_CPU_THRESHOLD_NON_CRITICAL = (tmp2[0]);
            UPPER_CPU_THRESHOLD_CRITICAL = (tmp2[1]);
            UPPER_CPU_THRESHOLD_FATAL = (tmp2[2]);;
        }
    }	

    /*Get FAN present .*/
    memset(resultA, 0x0, sizeof(resultA));
    exec_shell("psme.sh get fan_presence", resultA);
    if(strlen(resultA) !=0 )
    {  	   
        fan_presence = atoi(resultA);

        /*Get FAN info.*/
        {
            memset(resultA, 0x0, sizeof(resultA));
            exec_shell("psme.sh get fan_rear_speed_rpm", resultA);
            sscanf(resultA, " %d %d %d %d %d %d %d %d" ,  &tmp1[0] , &tmp1[1], &tmp1[2], &tmp1[3], &tmp1[4], &tmp1[5], &tmp1[6], &tmp1[7]);
            auto &fan_manager = agent_framework::module::ChassisComponents::get_instance()->get_fan_manager();

            auto fan_uuids = fan_manager.get_keys();
            for (const auto& fan_uuid : fan_uuids) 
            {
                auto fan_ = fan_manager.get_entry_reference(fan_uuid);  //Get Fan object by fan_uuid//

                if (fan_->get_fan_id() == i+1) 
                {
                    fan_->set_current_speed(tmp1[i++]);
                }

                // Check FAN present //
                unsigned int m_bit = (1 << id);
                unsigned int p_bit  = ((pre_fan_presence & m_bit) >> id);
                unsigned int c_bit  = ((fan_presence  & m_bit) >> id) ;

                RFLogEntry Entry;

                if((p_bit == 1) && (c_bit == 0))
                { // FAN unplug
                    std::string event("Event");
                    std::string servrity("OK");					   
                    std::string sensor_type("Fan");		   
                    std::string message("FAN unplug.");
                    Entry.set_log_entry(event , sensor_type , servrity, message, id+1);

                }
                else if((p_bit == 0) && (c_bit == 1))
                { // FAN plug in
                    std::string event("Event");
                    std::string servrity("OK");					   
                    std::string sensor_type("Fan");		   
                    std::string message("FAN plug in.");	
                    Entry.set_log_entry(event , sensor_type , servrity, message, id+1);				   
                }  
                id++;			
            }
        }
        pre_fan_presence = fan_presence;	   		
    }

    /*Get PSU info.*/

    memset(resultA, 0x0, sizeof(resultA));
    exec_shell("psme.sh get psu_presence", resultA);

    if(strlen(resultA) !=0 )
    { 	
        psu_presence = atoi(resultA);
        i = 0;
        id=0;		 
        memset(resultA, 0x0, sizeof(resultA));
        exec_shell("psme.sh get psu_power_out", resultA);
        sscanf(resultA, " %d %d" ,  &tmp1[0] , &tmp1[1]);

        auto &psu_manager = agent_framework::module::ChassisComponents::get_instance()->get_psu_manager();

        auto psu_uuids = psu_manager.get_keys();

        for (const auto& psu_uuid : psu_uuids) 
        {
            auto psu_ = psu_manager.get_entry_reference(psu_uuid);  //Get Psu object by psu_uuid//

            if (psu_->get_psu_id() == i+1) 
            {
                psu_->set_power_output(tmp1[i++]);
            }

            // Check PSU present //
            unsigned int m_bit = (1 << id);
            unsigned int p_bit  = ((pre_psu_presence & m_bit) >> id);
            unsigned int c_bit  = ((psu_presence  & m_bit) >> id) ;

            RFLogEntry Entry;			

            if((p_bit == 1) && (c_bit == 0))
            { // PSU unplug
                std::string event("Event");
                std::string servrity("OK");					   
                std::string sensor_type("Fan");		   
                std::string message("PSU unplug.");    
                Entry.set_log_entry(event , sensor_type , servrity, message, id+1);				   

            }
            else if((p_bit == 0) && (c_bit == 1))
            { // PSU plug in
                std::string event("Event");
                std::string servrity("OK");					   
                std::string sensor_type("Fan");		   
                std::string message("PSU plug in..");    
                Entry.set_log_entry(event , sensor_type , servrity, message, id+1);	                   
            }  
            id++;					 
        }
        pre_psu_presence = psu_presence;	   		
    }
    /*Sent PSU power comsum by lldp  .*/

    // Clean previous data //
#ifndef COMCAST	
    memset(resultA, 0x0, sizeof(resultA));	
    sprintf(lldpcmd,"/usr/local/sbin/lldpcli unconfigure lldp custom-tlv");
    exec_shell(lldpcmd, resultA);

    memset(resultA, 0x0, sizeof(resultA));	
    exec_shell("psme.sh get psu_power_out_sum", resultA);
    if(strlen(resultA) !=0 )
    {  	   
        sprintf(lldpcmd,"/usr/local/sbin/lldpcli configure lldp custom-tlv add oui 00,00,e8 subtype 1 oui-info 4d,4f,44,50,57,52,3a,%s", resultA);
        exec_shell(lldpcmd, resultA);
    }
#endif
    /*Get Thermal sensor info.*/
    i = 0;
    memset(resultA, 0x0, sizeof(resultA));
    exec_shell("psme.sh get thermal_sensor", resultA);
    sscanf(resultA, " %d %d %d %d %d %d %d %d" ,  &tmp1[0] , &tmp1[1], &tmp1[2], &tmp1[3], &tmp1[4], &tmp1[5], &tmp1[6], &tmp1[7]);

    auto &tz_manager = agent_framework::module::ChassisComponents::get_instance()->get_thermal_zone_manager();

    auto tz_uuids = tz_manager.get_keys();
    for (const auto& tz_uuid : tz_uuids) 
    {
        auto tz_ = tz_manager.get_entry_reference(tz_uuid);  //Get Psu object by psu_uuid//

        RFLogEntry Entry;
        std::string event("Event");

        if (tz_->get_tz_id() == i+1) 
        { 
            //To log //
            if(i==0)//CPU
            {		   
                if((tmp1[i] < ZERO) || ((tmp1[i]  < UPPER_CPU_THRESHOLD_CRITICAL) && (tmp1[i]  >= UPPER_CPU_THRESHOLD_NON_CRITICAL)))
                {

                    std::string servrity("Warning");					   
                    std::string sensor_type("Temperature");		   
                    std::string message("CPU Thermal Sensor over critical temp.");    
                    Entry.set_log_entry(event , sensor_type , servrity, message, i+1);	                                     
                }
                else if((tmp1[i]  < UPPER_CPU_THRESHOLD_FATAL) && ((tmp1[i]  >= UPPER_CPU_THRESHOLD_CRITICAL)))
                {
	
                    std::string servrity("Warning");					   
                    std::string sensor_type("Temperature");		   
                    std::string message("CPU Thermal Sensor over critical temp.");    
                    Entry.set_log_entry(event , sensor_type , servrity, message, i+1);									 
                }
                else if((tmp1[i]  >= UPPER_CPU_THRESHOLD_FATAL))
                {
	
                    std::string servrity("Warning");					   
                    std::string sensor_type("Temperature");		   
                    std::string message("CPU Thermal Sensor over fatal temp.");    
                    Entry.set_log_entry(event , sensor_type , servrity, message, i+1);									 
                }		   
            }
            else
            {		   
                if((tmp1[i] < ZERO) || ((tmp1[i]  < UPPER_SYS_THRESHOLD_CRITICAL) && (tmp1[i]  >= UPPER_SYS_THRESHOLD_NON_CRITICAL)))
                {
 
                    std::string servrity("Warning");					   
                    std::string sensor_type("Temperature");		   
                    std::string message("System Thermal Sensor over critical temp.");    
                    Entry.set_log_entry(event , sensor_type , servrity, message, i+1);	                                 
                }
                else if((tmp1[i]  < UPPER_SYS_THRESHOLD_FATAL) && ((tmp1[i]  >= UPPER_SYS_THRESHOLD_CRITICAL)))
                {

                    std::string servrity("Warning");					   
                    std::string sensor_type("Temperature");		   
                    std::string message("System Thermal Sensor over critical temp.");    
                    Entry.set_log_entry(event , sensor_type , servrity, message, i+1);									 
                }
                else if((tmp1[i]  >= UPPER_SYS_THRESHOLD_FATAL))
                {
		
                    std::string servrity("Warning");					   
                    std::string sensor_type("Temperature");		   
                    std::string message("System Thermal Sensor over fatal temp.");    
                    Entry.set_log_entry(event , sensor_type , servrity, message, i+1);									 
                }		   
            }

            tz_->set_temperature(tmp1[i++]);  
        }		   
    }
#endif
}

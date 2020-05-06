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

#include "psme/rest/endpoints/endpoint_base.hpp"
#include "psme/rest/server/error/error_factory.hpp"
#include "psme/rest/server/mux/matchers.hpp"
#include "psme/rest/session/manager/session_manager.hpp"
#include "psme/rest/validators/json_validator.hpp"
#include "psme/rest/account/manager/account_manager.hpp"
#include "psme/rest/account/model/accountservice.hpp" 
#include "psme/rest/endpoints/message_privilege_registry_file.hpp"
#include "psme/rest/registries/managers/message_registry_file_manager.hpp"


#include <locale>
#include <chrono>

using namespace psme::rest::server;
using namespace psme::rest::endpoint;
using namespace psme::rest::session::manager;
using namespace psme::rest::validators;
using namespace psme::rest::account::manager;

namespace {
constexpr std::size_t TIME_BUFFER_SIZE = 26;

std::string get_current_time() {
    char time_buffer[TIME_BUFFER_SIZE];
    auto now = std::chrono::system_clock::now();
    auto time_now = std::chrono::system_clock::to_time_t(now);

    tzset();

    struct tm local_tm;
    localtime_r(&time_now, &local_tm);
    std::strftime(time_buffer, TIME_BUFFER_SIZE, "%FT%H:%M", &local_tm);

    return time_buffer;
}

}

void psme::rest::server::http_method_not_allowed(const Request&, Response& response) {
    auto message = "Requested operation is not allowed on this resource.";
    auto error = error::ErrorFactory::create_method_not_allowed_error(message);

    response.set_status(error.get_http_status_code());
    response.set_body(error.as_string());
}


void psme::rest::server::http_method_not_authorized(const Request&, Response& response) {
    auto message = "Requested operation is not authorized.";
    auto error = error::ErrorFactory::create_unauthorized_error(message);

    response.set_status(error.get_http_status_code());
    response.set_body(error.as_string());
}


EndpointBase::EndpointBase(const std::string& path)
    : MethodsHandler(path), m_modified_time{::get_current_time()} {}

EndpointBase::~EndpointBase() {}

void EndpointBase::update_modified_time() {
    m_modified_time = ::get_current_time();
}

unsigned int get_op_pri_or(Json::Value Privilege);
unsigned int get_op_pri_or(Json::Value Privilege)
{
    int max_Pri = Privilege.size();
    unsigned int tt_Pri = 0;

    for (int j = 0; j < max_Pri; j++)
    {
        if (Privilege[j] == "Login")
            tt_Pri |= P_LOGIN;
        else if (Privilege[j] == "ConfigureManager")
            tt_Pri |= P_CONFIGUREMANAGER;
        else if (Privilege[j] == "ConfigureUsers")
            tt_Pri |= P_CONFIGUREUSERS;
        else if (Privilege[j] == "ConfigureSelf")
            tt_Pri |= P_CONFIGURESELF;
        else if (Privilege[j] == "ConfigureComponents")
            tt_Pri |= P_CONFIGURECOMPONENTS;
        else
            printf("No!");
    }

    return tt_Pri;
}

unsigned int EndpointBase::privilege_ov_check(const Request& request, std::string method, Json::Value PrOv, unsigned int user_privilege)
{
    printf("privilege_ov_check\r\n");
    unsigned int t_Pri = 0;
    int max_PrOv = PrOv.size();
    if (max_PrOv > 0)
    {
        for (int ii = 0; ii < max_PrOv; ii++)
        {
            std::string body = request.get_body();
            std::cout << "body[" << body << "]" << '\n';
            printf("ov In Map\r\n");
            Json::Value targets = PrOv[ii]["Targets"];
            int max_Targets = targets.size();

            for (int k = 0; k < max_Targets; k++)
            {
                std::string t = targets[k].asString();
                std::size_t fd = body.find(t);
                if (fd != std::string::npos)
                {
                    printf("Target[%s] in body PATCH\r\n", t.c_str());
                    Json::Value OpMapsMethod_ov = PrOv[ii]["OperationMap"][method];
                    int max_OpMaps_ov = OpMapsMethod_ov.size();
                    if (max_OpMaps_ov == 1)
                    {
                        // AND privilege
                        Json::Value Privilege_ov = OpMapsMethod_ov[0]["Privilege"];
                        t_Pri = get_op_pri_or(Privilege_ov);

                        unsigned int f = (t_Pri & user_privilege) & user_privilege;
                        printf("And Fin Pri[0x%x] user_privilege[%x] f[%x]\r\n", t_Pri, user_privilege, f);
                        if ((t_Pri == f) && t_Pri != 0)
                        {
                            return 1;
                        }
                        else
                        {
                            printf("ov No auth!!\r\n");
                            return 0;
                        }
                    }
                    else if (max_OpMaps_ov > 1)
                    {
                        // OR privilege
                        t_Pri = 0;
                        for (int kk = 0; kk < max_OpMaps_ov; kk++)
                        {
                            Json::Value Privilege_ov_m = OpMapsMethod_ov[kk]["Privilege"];
                            t_Pri |= get_op_pri_or(Privilege_ov_m);
                            unsigned int f = (t_Pri & user_privilege) & user_privilege;
                            printf("Or Fin Pri[0x%x] user_privilege[%x] f[%x]\r\n", t_Pri, user_privilege, f);
                            if ((t_Pri & f) && t_Pri != 0)
                            {
                                printf("ov OR auth!!\r\n");
                                return 1;
                            }
                            else
                            {
                                printf("ov OR No auth!!\r\n");
                            }
                        }
                    }
                    else
                    {
                        printf("ov OR No auth!! not have method can get\r\n");
                        return 0;
                    }
                }
                else
                {
                    printf("target not found in body\r\n");
                }
            }
            printf("ov all target pass in auth!!, others items checks by upper layer \r\n");
            return 1;
        }
    }
    printf("ov not found!!\r\n");
    return 0;
}

unsigned int EndpointBase::privilege_check(const Request& request, std::string method, unsigned int user_privilege, std::string role)
{
    try
    {
        printf("privilege_check user_privilege[0x%x] method[%s] role[%s]\r\n", user_privilege, method.c_str(), role.c_str());
        const auto &file = registries::MessageRegistryFileManager::get_instance()->get_file_by_id(2);
        Json::Value Jsons = file.get_pri_json()["Mappings"];
        int max_entity = Jsons.size();

        std::string body = request.get_body();
        std::cout << "pri chk body[" << body << "]" << '\n';

        for (int i = 0; i < max_entity; i++)
        {
            std::string entity_name = Jsons[i]["Entity"].asString().c_str();
            std::size_t found = request.get_url().find(entity_name);
            if (found != std::string::npos)
            {
                Json::Value OpMapsMethod = Jsons[i]["OperationMap"][method];
                int max_OpMaps = OpMapsMethod.size();
                unsigned int t_Pri = 0;

                if (max_OpMaps == 1)
                {
                    Json::Value Privilege_a = OpMapsMethod[0]["Privilege"];
                    t_Pri = get_op_pri_or(Privilege_a);
                    if (Jsons[i].isMember("PropertyOverrides"))
                    {
                        if (privilege_ov_check(request, method, Jsons[i]["PropertyOverrides"], user_privilege))
                        {
                            printf("ov chk ok\r\n");
                            return 1;
                        }
                    }

                    unsigned int f = (t_Pri & user_privilege) & user_privilege;
                    printf("And Fin Pri[0x%x] user_privilege[%x] f[%x]\r\n", t_Pri, user_privilege, f);
                    if ((t_Pri == f) && t_Pri != 0)
                    {
                        return 1;
                    }
                    else
                    {
                        printf("No auth!!\r\n");
                        return 0;
                    }
                }
                else if (max_OpMaps > 1)
                {
                    //Todo: Check "OR" privilege group of Entity in Privilege file
                    for (int ll = 0; ll < max_OpMaps; ll++)
                    {
                        Json::Value Privilege_o = OpMapsMethod[ll]["Privilege"];
                        t_Pri |= get_op_pri_or(Privilege_o);
                        unsigned int f = (t_Pri & user_privilege) & user_privilege;
                        printf("And Fin Pri[0x%x] user_privilege[%x] f[%x]\r\n", t_Pri, user_privilege, f);
                        if ((t_Pri == f) && t_Pri != 0)
                        {
                            printf("OR auth!!\r\n");
                            return 1;
                        }
                        else
                            printf("OR No auth!! go on!\r\n");
                    }
                }
                else
                {
                    printf("OR No auth!! can't get method\r\n");
                    return 0;
                }
            }
            else
                std::cout <<  "not found entity" << entity_name <<'\n';
        }
        return 0;
    }
    catch (const agent_framework::exceptions::NotFound &ex)
    {
        log_error(GET_LOGGER("rest"), "privilege_check Not found exception: " << ex.what());
        return 0;
    }
}

bool EndpointBase::authen_check(const Request &request, const std::string &method)
{
    try
    {
    std::string username{};
    std::string password{};
    std::string token{};
    std::string srcip{};
    token	= request.get_header("xAuthGen");
    username	= request.get_header("UserName");
    password	= request.get_header("Password");
    srcip       = request.get_header("SrcIp");
 	
        std::cout << "url[" << request.get_url() << "]token[" << token << "]"
                  << "username[" << username << "]"
                  << "password[" << password << "]"
                  << "srcip[" << srcip << "]";

    bool SessionServiceEnable = SessionManager::get_instance()->GetSessionConfigEnable();	
    bool BasicAuthenEnable = SessionManager::get_instance()->GetBasicAuthenServiceConfigEnable();	

    if((SessionServiceEnable == false) && (BasicAuthenEnable == false) )
        return true;
    else 
    {
        if( (token.length() !=0) && (SessionServiceEnable == true))
        { // Use Session Authen //
            int session_size = SessionManager::get_instance()->Session_size();
            if (session_size != 0)
            {
                if (SessionManager::get_instance()->updateSessionTimestamp(token, srcip) == true)
                {
                    Session new_session = SessionManager::get_instance()->getSession_by_Token(token);
                    const auto &account = AccountManager::get_instance()->getAccount(new_session.get_username());

                        /*Check if this account username locked*/
                        if (account.get_locked() == true)
                            return false;

                        /*Check if this account enabled*/
                        if (account.get_enabled() != true)
                        return false;

                        if (privilege_check(request, method, account.get_privilege(), account.get_roleid()))
                    return true;
                        else
                            return false;
                }
                else
                    return false;
            }
            else
                return false;
        }
        else if((username.length()!=0 && password.length() !=0) && (BasicAuthenEnable == true))
        {   //Use Basic Authen //
            const auto  & account  =AccountManager::get_instance()->getAccount(username);	

            /*Check if this account username locked*/
            if(account.get_locked() == true)
                return false;

            /*Check if this account enabled*/
            if(account.get_enabled() != true)
                return false;
			
                if (privilege_check(request, method, account.get_privilege(), account.get_roleid()))
                    return true;
                else
                return false;			 	

            int res  =AccountManager::get_instance()->login(username, password);	

            if(res == 0)
                return true;
            else if(res > Accountservice::get_instance()->get_aflt())
            {
                log_error(GET_LOGGER("rest"), "user [" << username << "] over AuthFailureLoggingThreshold login times !!");
                 return false;			
             }
             else
                 return false;
	 }
        else		
	     return false;
    }
}
    catch (const agent_framework::exceptions::NotFound &ex)
    {
        log_error(GET_LOGGER("rest"), "authen_check Not found exception: " << ex.what());
        return false;
    }
}

void EndpointBase::get(const Request& request, Response& response) {
    http_method_not_allowed(request, response);
}

void EndpointBase::del(const Request& request, Response& response) {
    http_method_not_allowed(request, response);
}

void EndpointBase::post(const Request& request, Response& response) {
    http_method_not_allowed(request, response);
}

void EndpointBase::patch(const Request& request, Response& response) {
    http_method_not_allowed(request, response);
}

void EndpointBase::put(const Request& request, Response& response) {
    http_method_not_allowed(request, response);
}

/*Nick Added Begin: */
void EndpointBase::exec_shell(const char* cmd, char * result_a)
{
    char buffer[512];
    char tcommand[512];
    std::string result = "";
    int timeout = 9; //Set timeout to 9 second to avoid command no response.
    sprintf(tcommand, "timeout %d %s", timeout ,cmd);
    FILE* pipe = popen(tcommand, "r");

    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (!feof(pipe)) {
            if (fgets(buffer, 512, pipe) != NULL)
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

/*Nick Added End  : */

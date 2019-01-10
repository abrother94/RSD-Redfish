/**
 * Copyright (c)  2015-2017 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <semaphore.h>
#include <pthread.h>

#include "libjsonrpc/jsonrpc.h"
#include "libcfg/cfg.h"
#include "libutils/sock.h"
#include "liblog/log.h"
#include "libjsonrpcapi/utils.h"

static int fd = 0;

int connect_asset_module(int port)
{
	fd = udp_connect(INADDR_LOOPBACK, port);
	if (fd < 0) {
		rmm_log(ERROR, "Connect asset module failed...\n");
		return -1;
	}
	return 0;
}

int send_msg_to_asset_module(jrpc_req_pkg_t *req, jrpc_rsp_pkg_t *rsp, int evt_id)
{
	int rc = -1;
	rc = send_msg_to_fd(req, rsp, evt_id, fd);
	return rc;
}

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
*/

#ifndef __SASL_WRAPPER_H__
#define __SASL_WRAPPER_H__

#include <stdint.h>
#include <sasl/sasl.h>


/**
 * ClientImpl holds the necesary information for a sasl client.
 */
typedef struct ClientImpl_struct {
    sasl_conn_t* ci_conn;
    sasl_callback_t ci_callbacks[8];
    int ci_cbIndex;
    char *ci_error;
    char *ci_serviceName;
    char *ci_userName;
    char *ci_authName;
    char *ci_password;
    char *ci_hostName;
    char *ci_externalUserName;
    uint32_t ci_maxBufSize;
    uint32_t ci_minSsf;
    uint32_t ci_maxSsf;
    uint32_t ci_externalSsf;
    sasl_secret_t* ci_secret;
    
} ClientImpl;

/**
 * initialized detetrmines whether or not the sasl client library has 
 * been initialized.
 */
extern int initialized;


/**
 * newClient creates a new sasl client.
 */
ClientImpl* newClient();

/**
 * freeClient frees an allocated client.
 */
void freeClient(ClientImpl *ci);
   
/**
 * init initializes a sasl client. init should only be called after all the
 * properties have been set. init returns -1 for an error and 0 on a 
 * successful initialization.
 */
int init(ClientImpl *ci);

/**
 * functions to safely set attributes inside of the client.
 */
int setService(ClientImpl *ci, const char *service);
int setAuthName(ClientImpl *ci, const char *authName);
int setPassword(ClientImpl *ci, const char *password);
int setHost(ClientImpl *ci, const char *hostName);
int setExternalUserName(ClientImpl *ci, const char *externalUserName);
void setMinSsf(ClientImpl *ci, uint32_t minSsf);
void setMaxSsf(ClientImpl *ci, uint32_t maxSsf);

/**
 * addCallback appends proc with id to the end of the callback list.
 */
void addCallback(ClientImpl *ci, unsigned long id, void *proc);

/**
 * cbName is a callback for the sasl library to call requesting ClientImpl's 
 * userName or authName.
 */
int cbName(void *context, int id, const char **result, unsigned *len);

/**
 * cbPassword is a callback for the sasl library to call 
 */
int cbPassword(sasl_conn_t *conn, void *context, int id, 
        sasl_secret_t **psecret);

/**
 * start starts a sasl connection
 */
int start(ClientImpl *ci, const char *mechList, const char **chosen, 
        const char **initialResponse);

/**
 * step takes the next step in initiating a sasl connection
 */
int step(ClientImpl *ci, const char *challenge, unsigned int challenge_len, 
        const char **response);

/**
 * encode encodes data for communication with the server
 */
int encode(ClientImpl *ci, const char *clearText, unsigned int clearText_len,
                const char **cipherText, unsigned int *cipherText_len);

/**
 * decode decodes data recieved from the server
 */
int encode(ClientImpl *ci, const char *clearText, unsigned int clearText_len,
                const char **cipherText, unsigned int *cipherText_len);

/**
 * interact prompts a user of information.
 */
void interact(sasl_interact_t* prompt);

/**
 * setError sets the ci_error field of ClientImpl to a formatted version of an 
 * error. If text is NULL, the error code will be looked up from sas_errdetail
 * or from sasl_errstring (whichever is most appropriate).  If text2 is NULL, 
 * then it is not included in the formatted string.
 */
void setError(ClientImpl *ci, const char *context, int code, const char *text);
void setError2(ClientImpl *ci, const char *context, int code, const char *text, const char *text2);

#endif


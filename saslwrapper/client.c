#include "saslwrapper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// initialized is set to 0 since the sasl library has not be initialized yet.
int initialized = 0;

ClientImpl* newClient() {

    ClientImpl *ci = (ClientImpl *)malloc(sizeof(ClientImpl));
    memset(ci, 0, sizeof(ClientImpl));

    ci->ci_conn = NULL;
    ci->ci_cbIndex = 0;
    ci->ci_maxBufSize = 65535;
    ci->ci_minSsf = 0;
    ci->ci_maxSsf = 65535;
    ci->ci_externalSsf = 0;
    ci->ci_secret = NULL;

    return ci;
}

void freeClient(ClientImpl *ci) {
    if( !ci )
        return;

    if( ci->ci_conn ) {
        sasl_dispose(&ci->ci_conn);
        ci->ci_conn = NULL;
    }
    free(ci);
}

int init(ClientImpl *ci) {
    
    int result;

    if (!initialized) {
        initialized = 1;
        result = sasl_client_init(0);
        if (result != SASL_OK) {
            setError(ci, "sasl_client_init", result, 
                    sasl_errstring(result, 0, 0));
            return -1;
        }
    }

    addCallback(ci, SASL_CB_GETREALM, 0);
    if (ci->ci_userName) {
        addCallback(ci, SASL_CB_USER, (void*)cbName);
        addCallback(ci, SASL_CB_AUTHNAME, (void*)cbName);

        if (ci->ci_password)
            addCallback(ci,SASL_CB_PASS, (void*) cbPassword);
        else
            addCallback(ci,SASL_CB_PASS, 0);
    }
    addCallback(ci,SASL_CB_LIST_END, 0);

    unsigned flags;

    flags = 0;
    if (ci->ci_authName && strcmp(ci->ci_authName, ci->ci_userName))
        flags |= SASL_NEED_PROXY;

    result = sasl_client_new(ci->ci_serviceName, ci->ci_hostName, 0, 0, 
            ci->ci_callbacks, flags, &ci->ci_conn);
    if (result != SASL_OK) {
        setError(ci, "sasl_client_new", result, sasl_errstring(result, 0, 0));
        return -1;
    }

    sasl_security_properties_t secprops;

    secprops.min_ssf = ci->ci_minSsf;
    secprops.max_ssf = ci->ci_maxSsf;
    secprops.maxbufsize = ci->ci_maxBufSize;
    secprops.property_names = 0;
    secprops.property_values = 0;
    secprops.security_flags = 0;

    result = sasl_setprop(ci->ci_conn, SASL_SEC_PROPS, &secprops);
    if (result != SASL_OK) {
        setError(ci,"sasl_setprop(SASL_SEC_PROPS)", result, NULL);
        sasl_dispose(&ci->ci_conn);
        ci->ci_conn = NULL;
        return -1;
    }

    if (ci->ci_externalUserName) {
        result = sasl_setprop(ci->ci_conn, SASL_AUTH_EXTERNAL, ci->ci_externalUserName);
        if (result != SASL_OK) {
            setError(ci,"sasl_setprop(SASL_AUTH_EXTERNAL)", result, NULL);
            sasl_dispose(&ci->ci_conn);
            ci->ci_conn = NULL;
            return -1;
        }

        result = sasl_setprop(ci->ci_conn, SASL_SSF_EXTERNAL, &ci->ci_externalSsf);
        if (result != SASL_OK) {
            setError(ci,"sasl_setprop(SASL_SSF_EXTERNAL)", result, NULL);
            sasl_dispose(&ci->ci_conn);
            ci->ci_conn = NULL;
            return -1;
        }
    }

    return 0;
}

int setService(ClientImpl *ci, const char *service) {
    if(ci->ci_serviceName)
        free(ci->ci_serviceName);
    ci->ci_serviceName = strdup(service);
    return 0;
}

int setAuthName(ClientImpl *ci, const char *authName) {
    if(ci->ci_authName)
        free(ci->ci_authName);
    ci->ci_serviceName = strdup(authName);
    return 0;
}

int setPassword(ClientImpl *ci, const char *password) {
    if(ci->ci_password)
        free(ci->ci_password);
    if(ci->ci_secret)
        free(ci->ci_secret);
    ci->ci_password = strdup(password);
    ci->ci_secret = (sasl_secret_t*) malloc(sizeof(sasl_secret_t) + 
            strlen(ci->ci_password));
    return 0;
}

int setHost(ClientImpl *ci, const char *hostName) {
    if(ci->ci_hostName)
        free(ci->ci_hostName);
    ci->ci_hostName = strdup(hostName);
    return 0;
}

int setExternalUserName(ClientImpl *ci, const char *externalUserName) {
    if(ci->ci_externalUserName) 
        free(ci->ci_externalUserName);
    ci->ci_externalUserName = strdup(externalUserName);
    return 0;
}

void setMinSsf(ClientImpl *ci, uint32_t minSsf) {
    ci->ci_minSsf = minSsf;
}

void setMaxSsf(ClientImpl *ci, uint32_t maxSsf) {
    ci->ci_maxSsf = maxSsf;
}

void setExternalSsf(ClientImpl *ci, uint32_t externalSsf) {
    ci->ci_externalSsf = externalSsf;
}

void setMaxBufSize(ClientImpl *ci, uint32_t maxBufSize) {
    ci->ci_maxBufSize = maxBufSize;
}

int start(ClientImpl *ci, const char *mechList, const char **chosen, const char **initialResponse) {
    int result;
    sasl_interact_t* prompt = NULL;
    const char* resp = NULL;
    const char* mech = NULL;
    unsigned int len = 0;

    do {
        result = sasl_client_start(ci->ci_conn, mechList, &prompt, &resp, &len, &mech);
        if (result == SASL_INTERACT)
            interact(prompt);
    } while (result == SASL_INTERACT);

    if (result != SASL_OK && result != SASL_CONTINUE) {
        setError(ci,"sasl_client_start", result, NULL);
        return -1;
    }

    *chosen = strdup(mech);
    *initialResponse = (const char *)malloc(len);
    memcpy((char *)*initialResponse, resp, len);
    return 0;
}

int step(ClientImpl *ci, const char *challenge, unsigned int challenge_len, const char **response) {
    int result;
    sasl_interact_t* prompt = 0;
    const char* resp;
    unsigned int len;

    do {
        result = sasl_client_step(ci->ci_conn, challenge, challenge_len, &prompt, &resp, &len);
        if (result == SASL_INTERACT)
            interact(prompt);
    } while (result == SASL_INTERACT);
    if (result != SASL_OK && result != SASL_CONTINUE) {
        setError(ci,"sasl_client_step", result, NULL);
        return -1;
    }

    *response = (const char *)malloc(len);
    memcpy((char *)*response, resp, len);
    return 0;

}

int encode(ClientImpl *ci, const char *clearText, unsigned int clearText_len, 
        const char **cipherText, unsigned int *cipherText_len)
{
    const char* output;
    unsigned int outlen;
    int result = sasl_encode(ci->ci_conn, clearText, clearText_len, &output, &outlen);
    if (result != SASL_OK) {
        setError(ci, "sasl_encode", result, NULL);
        return -1;
    }
    
    *cipherText = (const char *)malloc(outlen);
    memcpy((char *)*cipherText, output, outlen);
    return 0;
}

int decode(ClientImpl *ci, const char *cipherText, unsigned int cipherText_len, 
        const char **clearText, unsigned int *clearText_len)
{
    unsigned int i, niters, remaining, outlen, total_len;
    const char* output; 
    char *citer;
    char **decodings;
    unsigned int *decoding_lens;

    // return error for empty string
    if( cipherText_len == 0 )
        return -1;

    // calculate the number of decodings, store them, then append them
    total_len = 0;
    citer = (char *)cipherText;
    remaining = cipherText_len;
    niters = (cipherText_len - 1) / ci->ci_maxBufSize + 1;
    decodings = (char **)malloc(sizeof(char *)*niters);
    decoding_lens = (unsigned int *)malloc(sizeof(unsigned int)*niters);

    for( i = 0; i < niters; i++ ) {
        unsigned int seg_len = (remaining < ci->ci_maxBufSize) ? remaining : 
                  ci->ci_maxBufSize;
        int result = sasl_decode(ci->ci_conn, (const char *)citer, seg_len, &output, &outlen);
        if (result != SASL_OK) {
            setError(ci, "sasl_decode", result, NULL);
            if( i ) {
                niters = i;
                for( i = 0; i < niters; ++i)
                    free(decodings[i]);
            }
            free(decodings);
            free(decoding_lens);
            return -1;
        }
        citer += seg_len;
        decodings[i] = (char*)malloc(outlen);
        decoding_lens[i] = outlen;
        total_len += outlen;
    }

    *clearText = (const char *)malloc(total_len);
    citer = (char *)*clearText;
    for( i = 0; i < niters; i++ ){
        memcpy(citer, (const char *)decodings[i], decoding_lens[i]);
        citer += decoding_lens[i];
        free((void *)decodings[i]);
    }
    
    free((void *)decodings);
    free((void *)decoding_lens);
    return 0;
}

int getUserId(ClientImpl *ci, const char **user_id)
{
    int result;
    const char* operName;

    result = sasl_getprop(ci->ci_conn, SASL_USERNAME, (const void**) &operName);
    if (result != SASL_OK) {
        setError(ci, "sasl_getprop(SASL_USERNAME)", result, NULL);
        return -1;
    }

    *user_id = strdup(operName);
    return 0;
}

int getSSF(ClientImpl *ci, int *ssf)
{
    int result = sasl_getprop(ci->ci_conn, SASL_SSF, (const void **)&ssf);
    if (result != SASL_OK) {
        setError(ci, "sasl_getprop(SASL_SSF)", result, NULL);
        return -1;
    }

    return 0;
}


/**
 * getError returns a copy of the error stored in the client. This is a 
 * malloc'ed string, so it is up to the developer to free it after use.
 */
char* getError(ClientImpl *ci)
{
    char *ret;

    if( ci->ci_error ){
        ret = (char *)malloc(strlen(ci->ci_error) + 1);
        strcpy(ci->ci_error, ret);
    }else{
        ret = (char *)malloc(sizeof("no error"));
        strcpy(ret,"no error");
    }

    return ret;
}

void setError(ClientImpl *ci, const char *context, int code, const char *text) {
    setError2(ci, context, code, text, NULL);
}

void setError2(ClientImpl *ci, const char *context, int code, const char *text, const char *text2) {
    size_t len;

    if( !text ){ 
        if( ci->ci_conn ) {
            text = (char *)sasl_errdetail(ci->ci_conn);
        } else {
            text = (char *)sasl_errstring(code, NULL, NULL);
        }
    } 

    // add up the max length. 20 for the integer, 
    len = strlen(context) + strlen(text) + 20 + sizeof("Error in  ()  - ");
    if( !text2 )
        len += strlen(text2);
    ci->ci_error = (char *)malloc(len);
    if( !text2 )
        sprintf(ci->ci_error, "Error in %s (%d) %s", context, code, text);
    else
        sprintf(ci->ci_error, "Error in %s (%d) %s - %s", context, code,
                text, text2);
}


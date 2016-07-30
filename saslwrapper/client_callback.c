#include "saslwrapper.h"

#include <stdlib.h>
#include <string.h>

void addCallback(ClientImpl *ci, unsigned long id, void* proc)
{
    ci->ci_callbacks[ci->ci_cbIndex].id = id;
    ci->ci_callbacks[ci->ci_cbIndex].proc = (int (*)()) proc;
    ci->ci_callbacks[ci->ci_cbIndex].context = ci;
    ci->ci_cbIndex++;
}

int cbName(void *context, int id, const char **result, unsigned *len)
{
    ClientImpl* ci = (ClientImpl*) ci;

    if (id == SASL_CB_USER || (id == SASL_CB_AUTHNAME && !ci->ci_authName)) {
        *result = ci->ci_userName;
        //*len    = strlen(ci->ci_userName);
    } else if (id == SASL_CB_AUTHNAME) {
        *result = ci->ci_authName;
        //*len    = strlen(ci->ci_authName);
    }

    return SASL_OK;
}

int cbPassword(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret)
{
    ClientImpl* ci = (ClientImpl*) context;
    size_t length = strlen(ci->ci_password);

    if (id == SASL_CB_PASS) {
        ci->ci_secret->len = length;
        memcpy(ci->ci_secret->data, ci->ci_password, length);
    } else
        ci->ci_secret->len = 0;

    *psecret = ci->ci_secret;
    return SASL_OK;
}

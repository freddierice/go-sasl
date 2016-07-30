#include "saslwrapper.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

void interact(sasl_interact_t* prompt) {
    char *tmp_prompt;
    size_t len;

    // TODO: add support for a non getpass solution

    len = strlen(prompt->prompt) + sizeof(": ");
    if( prompt->defresult)
        len += strlen(prompt->defresult) + sizeof(" []");
    tmp_prompt = (char *)malloc(len);
    if( prompt->defresult )
        sprintf(tmp_prompt, "%s [%s]: ", prompt->prompt, prompt->defresult);
    else
        sprintf(tmp_prompt, "%s: ", prompt->prompt);

    prompt->result = NULL;
    len = 0;
    getline((char **)&prompt->result, &len, stdin);
    prompt->len = len;
}

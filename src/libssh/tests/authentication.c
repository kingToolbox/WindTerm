/*
This file is distributed in public domain. You can do whatever you want
with its content.
*/


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <libssh/libssh.h>

#include "tests.h"
static int auth_kbdint(SSH_SESSION *session){
    int err=ssh_userauth_kbdint(session,NULL,NULL);
    char *name,*instruction,*prompt,*ptr;
    char buffer[128];
    int i,n;
    char echo;
    while (err==SSH_AUTH_INFO){
        name=ssh_userauth_kbdint_getname(session);
        instruction=ssh_userauth_kbdint_getinstruction(session);
        n=ssh_userauth_kbdint_getnprompts(session);
        if(strlen(name)>0)
            printf("%s\n",name);
        if(strlen(instruction)>0)
            printf("%s\n",instruction);
        for(i=0;i<n;++i){
            prompt=ssh_userauth_kbdint_getprompt(session,i,&echo);
            if(echo){
                printf("%s",prompt);
                fgets(buffer,sizeof(buffer),stdin);
                buffer[sizeof(buffer)-1]=0;
                if((ptr=strchr(buffer,'\n')))
                    *ptr=0;
                ssh_userauth_kbdint_setanswer(session,i,buffer);
                memset(buffer,0,strlen(buffer));
            } else {
                ptr=getpass(prompt);
                ssh_userauth_kbdint_setanswer(session,i,ptr);
            }
        }
        err=ssh_userauth_kbdint(session,NULL,NULL);
    }
    return err;
}

int authenticate (SSH_SESSION *session){
    int auth=ssh_userauth_autopubkey(session, NULL);
    char *password;
    if(auth==SSH_AUTH_ERROR){
        fprintf(stderr,"Authenticating with pubkey: %s\n",ssh_get_error(session));
	    return auth;
    }
    if(auth!=SSH_AUTH_SUCCESS){
        auth=auth_kbdint(session);
        if(auth==SSH_AUTH_ERROR){
            fprintf(stderr,"authenticating with keyb-interactive: %s\n",
                    ssh_get_error(session));
            return auth;
        }
    }
    if(auth!=SSH_AUTH_SUCCESS){
        password=getpass("Password : ");
        auth = ssh_userauth_password(session,NULL,password);
        memset(password,0,strlen(password));
        if (auth==SSH_AUTH_ERROR){
            fprintf(stderr,"Authentication with password failed: %s\n",ssh_get_error(session));
            return auth;
        }
    }
    return auth;
}

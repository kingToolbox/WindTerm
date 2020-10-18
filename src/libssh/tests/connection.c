/*
This file is distributed in public domain. You can do whatever you want
with its content.
*/

#include <libssh/libssh.h>
#include <stdio.h>
#include "tests.h"
SSH_OPTIONS *set_opts(int argc, char **argv){
	SSH_OPTIONS *options=ssh_options_new();
	char *host=NULL;
	if(ssh_options_getopt(options,&argc, argv)){
	    fprintf(stderr,"error parsing command line :%s\n",ssh_get_error(options));
	    return NULL;
	}
    int i;
    while((i=getopt(argc,argv,""))!=-1){
        switch(i){
            default:
                fprintf(stderr,"unknown option %c\n",optopt);
        }
    }
    if(optind < argc)
        host=argv[optind++];
    if(host==NULL){
    	fprintf(stderr,"must provide an host name\n");
    	return NULL;
    }
    ssh_options_set_host(options,host);
    return options;
}

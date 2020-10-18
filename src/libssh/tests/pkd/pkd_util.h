/*
 * pkd_keyutil.h --
 *
 * (c) 2014 Jon Simons
 */

#ifndef __PKD_UTIL_H__
#define __PKD_UTIL_H__

int system_checked(const char *cmd);

/* Is client 'X' enabled? */
int is_openssh_client_enabled(void);
int is_dropbear_client_enabled(void);

#endif /* __PKD_UTIL_H__ */

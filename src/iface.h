/*
 ============================================================================
 Name        : iface.h
 Author      : Kevin Mahoney <kevin.mahoney@zenotec.net>
 Version     :
 Copyright   : Your copyright notice
 Description : Wireless packet concatenator
 ============================================================================
 */

#ifndef _IFACE_H_
#define _IFACE_H_

#include <net/if.h>
#include <netinet/if_ether.h>

typedef struct iface_info
{
    int ifindex;
    char ifname[IF_NAMESIZE + 1];
    char hwaddr[ETH_ALEN];
} iface_info_t;


#endif /* _IFACE_H_ */

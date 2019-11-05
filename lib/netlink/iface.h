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

#include "netlink.h"

typedef struct WcapIfaceInfo
{
    unsigned int ifindex;
    char ifname[IF_NAMESIZE + 1];
    uint32_t flags;
    uint8_t opstate;
    uint8_t linkstate;
    unsigned char hwaddr[ETH_ALEN];
    unsigned int mtu;
} WcapIfaceInfo_t;

bool WcapIfaceInfoGet(const char* ifname, WcapIfaceInfo_t* info);
bool WcapIfaceInfoSet(const char* ifname, WcapIfaceInfo_t* info);

bool WcapIfaceInetAddrAdd(const char *ifname, const char* addr, const int prefix);
bool WcapIfaceInetAddrRemove(const char *ifname, const char* addr, const int prefix);

#endif /* _IFACE_H_ */

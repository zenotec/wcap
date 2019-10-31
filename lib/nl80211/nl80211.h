/*
 ============================================================================
 Name        : nl80211.h
 Author      : Kevin Mahoney <kevin.mahoney@zenotec.net>
 Version     :
 Copyright   : Your copyright notice
 Description : Wireless packet capture and forwarder
 ============================================================================
 */

#ifndef _NL80211_H_
#define _NL80211_H_

#include <stdbool.h>

#include <linux/socket.h>
#include <net/if.h>
#include <linux/nl80211.h>

#include "iface.h"
#include "netlink.h"

typedef struct WcapPhyInfo
{
    int phyindex;
    char phyname[IF_NAMESIZE + 1];
} WcapPhyInfo_t;

typedef struct WcapWifaceInfo
{
    int ifindex;
    char ifname[IF_NAMESIZE + 1];
    int iftype;
    WcapPhyInfo_t phy;
    WcapIfaceInfo_t iface;
} WcapWifaceInfo_t;


bool WcapNL80211Connect();
bool WcapNL80211Disconnect();

bool WcapNL80211SetCallback(const enum nl_cb_type type, void* cb, void* arg);
bool WcapNL80211ClrCallback(const enum nl_cb_type type);

struct nl_msg* WcapNL80211NewMsg(const int cmd, const int flags);

bool WcapNL80211PhyInfoDump(WcapPhyInfo_t** list);
bool WcapNL80211PhyInfoGet(const int phyindex, WcapPhyInfo_t* info);
bool WcapNL80211PhyInfoSet(const int phyindex, WcapPhyInfo_t* info);

bool WcapNL80211WifaceCreate(WcapWifaceInfo_t* info);
bool WcapNL80211WifaceDelete(WcapWifaceInfo_t* info);
bool WcapNL80211WifaceGet(const char* ifname, WcapWifaceInfo_t* info);
bool nl80211_wiface_set(const char* ifname, WcapWifaceInfo_t* info);

bool nl80211_wiface_scan(const char* ifname);

#endif /* _NL80211_H_ */

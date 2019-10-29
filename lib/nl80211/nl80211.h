#ifndef _NL80211_H_
#define _NL80211_H_

#include <stdbool.h>

#include <linux/socket.h>
#include <net/if.h>
#include <linux/nl80211.h>

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
} WcapWifaceInfo_t;


bool WcapNl80211Connect();
bool WcapNl80211Disconnect();

bool WcapNl80211SetCallback(const enum nl_cb_type type, void* cb, void* arg);
bool WcapNl80211ClrCallback(const enum nl_cb_type type);

struct nl_msg* WcapNl80211NewMsg(const int cmd, const int flags);

bool nl80211_phyinfo_dump(WcapPhyInfo_t** list);
bool nl80211_phyinfo_get(const int phyindex, WcapPhyInfo_t* info);
bool nl80211_phyinfo_set(const int phyindex, WcapPhyInfo_t* info);

bool nl80211_wiface_new(WcapWifaceInfo_t* info);
bool nl80211_wiface_del(WcapWifaceInfo_t* info);
bool nl80211_wiface_get(const char* ifname, WcapWifaceInfo_t* info);
bool nl80211_wiface_set(const char* ifname, WcapWifaceInfo_t* info);

bool nl80211_wiface_scan(const char* ifname);

#endif /* _NL80211_H_ */

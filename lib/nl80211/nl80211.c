/*
 ============================================================================
 Name        : nl80211.c
 Author      : Kevin Mahoney <kevin.mahoney@zenotec.net>
 Version     :
 Copyright   : Your copyright notice
 Description : Wireless packet concatenator
 ============================================================================
 */

#include "nl80211.h"


bool WcapNL80211Connect()
{
    return WcapGENLConnect();
}

bool WcapNL80211Disconnect()
{
    return WcapGENLDisconnect();
}

bool WcapNL80211SetCallback(const enum nl_cb_type type, void* cb, void* arg)
{
    return WcapGENLSetCallback(type, cb, arg);
}

bool WcapNL80211ClrCallback(const enum nl_cb_type type)
{
    return WcapGENLClrCallback(type);
}

struct nl_msg* WcapNL80211NewMsg(const int cmd, const int flags)
{
    return WcapGENLNewMsg(NL80211_GENL_NAME, cmd, flags);
}


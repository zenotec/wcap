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


bool WcapNl80211Connect()
{
    return WcapGENLConnect();
}

bool WcapNl80211Disconnect()
{
    return WcapGENLDisconnect();
}

bool WcapNl80211SetCallback(const enum nl_cb_type type, void* cb, void* arg)
{
    return WcapGENLSetCallback(type, cb, arg);
}

bool WcapNl80211ClrCallback(const enum nl_cb_type type)
{
    return WcapGENLClrCallback(type);
}

struct nl_msg* WcapNl80211NewMsg(const int cmd, const int flags)
{
    return WcapGENLNewMsg(NL80211_GENL_NAME, cmd, flags);
}


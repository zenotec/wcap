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

struct iface_wrk
{
    int valid;
    WcapWifaceInfo_t* info;
};

static int _get_valid_cb(struct nl_msg* msg, void* arg)
{

    WcapWifaceInfo_t* info = (WcapWifaceInfo_t*)arg;
    struct nlattr *tb[CTRL_ATTR_MAX + 1] = { 0 };
    struct nlmsghdr *nlhdr = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlhdr);

    fprintf(stdout, "[%d] %s(%p, %p)\n", __LINE__, __FUNCTION__, msg, arg);

    // Parse all the attributes into the attribute table
    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    // Copy out attributes into caller's struct
    if (tb[NL80211_ATTR_WIPHY])
        info->phy.phyindex = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
    if (tb[NL80211_ATTR_IFINDEX])
        info->ifindex = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
    if (tb[NL80211_ATTR_IFNAME])
        strcpy(info->ifname, nla_get_string(tb[NL80211_ATTR_IFNAME]));
    if (tb[NL80211_ATTR_IFTYPE])
        info->iftype = nla_get_u32(tb[NL80211_ATTR_IFTYPE]);

    return NL_OK;
}

static int _get_finish_cb(struct nl_msg* msg, void* arg)
{
    fprintf(stdout, "[%d] %s(%p, %p)\n", __LINE__, __FUNCTION__, msg, arg);
    return NL_STOP;
}

static int _new_valid_cb(struct nl_msg* msg, void* arg)
{
    fprintf(stdout, "[%d] %s(%p, %p)\n", __LINE__, __FUNCTION__, msg, arg);
    return NL_OK;
}


bool nl80211_wiface_new(WcapWifaceInfo_t* info)
{

    struct nl_msg* msg = NULL;

    fprintf(stdout, "[%d] %s(%p)\n", __LINE__, __FUNCTION__, info);

    // Install callback
    if (!WcapGENLSetCallback(NL_CB_VALID, _new_valid_cb, NULL))
    {
        fprintf(stderr, "Cannot install callback: %s\n", info->ifname);
        return false;
    }

    // Create 'get interface' command message
    msg = WcapNl80211NewMsg(NL80211_CMD_NEW_INTERFACE, 0);
    if (msg == NULL)
    {
        return false;
    }

    fprintf(stdout, "[%d] %s(): Adding phy index: %d\n", __LINE__, __FUNCTION__, info->phy.phyindex);
    if (nla_put_u32(msg, NL80211_ATTR_WIPHY, info->phy.phyindex) != 0)
    {
        fprintf(stderr, "Error adding PHY index\n");
        return false;
    }

    fprintf(stdout, "[%d] %s(): Adding ifname: %s\n", __LINE__, __FUNCTION__, info->ifname);
    if (nla_put_string(msg, NL80211_ATTR_IFNAME, info->ifname) != 0)
    {
        fprintf(stderr, "Error adding PHY index\n");
        return false;
    }

    fprintf(stdout, "[%d] %s(): Adding iftype: %d\n", __LINE__, __FUNCTION__, info->iftype);
    if (nla_put_u32(msg, NL80211_ATTR_IFTYPE, info->iftype) != 0)
    {
        fprintf(stderr, "Error adding interface type\n");
        return false;
    }

    fprintf(stdout, "[%d] %s(): Sending:\n", __LINE__, __FUNCTION__);
    if (!WcapGENLSendMsg(msg))
    {
        fprintf(stderr, "Error sending netlink message\n");
        return false;
    }

    if (!WcapGENLRecvMsg(msg))
    {
        fprintf(stderr, "Error receiving netlink message\n");
        return false;
    }

    // Restore default callback
    if (!WcapGENLClrCallback(NL_CB_VALID))
    {
        fprintf(stderr, "Error restoring default callback\n");
        return false;
    }

    return true;
}

bool nl80211_wiface_del(WcapWifaceInfo_t* info)
{

    struct nl_msg* msg = NULL;

    fprintf(stdout, "[%d] %s(%p)\n", __LINE__, __FUNCTION__, info);

    // Install callback
    if (!WcapGENLSetCallback(NL_CB_VALID, _new_valid_cb, NULL))
    {
        fprintf(stderr, "Cannot install callback: %s\n", info->ifname);
        return false;
    }

    // Create 'get interface' command message
    msg = WcapNl80211NewMsg(NL80211_CMD_DEL_INTERFACE, 0);
    if (msg == NULL)
    {
        return false;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, info->ifindex) != 0)
    {
        fprintf(stderr, "Error adding interface index\n");
        return false;
    }

    fprintf(stdout, "[%d] %s(): Sending:\n", __LINE__, __FUNCTION__);
    if (!WcapGENLSendMsg(msg))
    {
        fprintf(stderr, "Error sending netlink message\n");
        return false;
    }

    if (!WcapGENLRecvMsg(msg))
    {
        fprintf(stderr, "Error receiving netlink message\n");
        return false;
    }

    // Restore default callback
    if (!WcapGENLClrCallback(NL_CB_VALID))
    {
        fprintf(stderr, "Error restoring default callback\n");
        return false;
    }

    return true;
}

bool nl80211_wiface_get(const char* ifname, WcapWifaceInfo_t* info)
{

    unsigned int ifindex = 0;
    struct nl_msg* msg = NULL;

    fprintf(stdout, "[%d] %s(%s, %p)\n", __LINE__, __FUNCTION__, ifname, info);

    // Lookup interface index by name
    ifindex = if_nametoindex(ifname);
    if (!ifindex)
    {
        // Don't print error message because the caller may only want to check if
        //   the interface exists or not
        return false;
    }

    // Initialized caller struct
    memset(info, 0, sizeof(WcapWifaceInfo_t));

    // Install callback
    if (!WcapGENLSetCallback(NL_CB_VALID, _get_valid_cb, info))
    {
        fprintf(stderr, "Cannot install callback: %s\n", ifname);
        return false;
    }
    if (!WcapGENLSetCallback(NL_CB_FINISH, _get_finish_cb, info))
    {
        fprintf(stderr, "Cannot install callback: %s\n", ifname);
        return false;
    }

    // Create 'get interface' command message
    msg = WcapNl80211NewMsg(NL80211_CMD_GET_INTERFACE, 0);
    if (msg == NULL)
    {
        return false;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) != 0)
    {
        fprintf(stderr, "Error adding interface index\n");
        return false;
    }

    if (!WcapGENLSendMsg(msg))
    {
        fprintf(stderr, "Error sending netlink message\n");
        return false;
    }

    if (!WcapGENLRecvMsg(msg))
    {
        fprintf(stderr, "Error receiving netlink message\n");
        return false;
    }

    // Restore default callback
    if (!WcapGENLClrCallback(NL_CB_VALID))
    {
        fprintf(stderr, "Error restoring default callback\n");
        return false;
    }
    if (!WcapGENLClrCallback(NL_CB_FINISH))
    {
        fprintf(stderr, "Error restoring default callback\n");
        return false;
    }

    fprintf(stdout, "[%d] %s()\n", __LINE__, __FUNCTION__);

    return nl80211_phyinfo_get(info->phy.phyindex, &info->phy);

}

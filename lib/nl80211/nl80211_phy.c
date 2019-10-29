
#include <net/if.h>

#include "nl80211.h"

#define PHY_MAXNUM      8
static WcapPhyInfo_t _phylist[PHY_MAXNUM] = { 0 }; // NOT THREAD SAFE

static void _nlattr2phyinfo(struct nlattr** tb, WcapPhyInfo_t* info)
{
    if (tb[NL80211_ATTR_WIPHY])
        info->phyindex = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
    if (tb[NL80211_ATTR_WIPHY_NAME])
        strncpy(info->phyname, nla_get_string(tb[NL80211_ATTR_WIPHY_NAME]), sizeof(info->phyname));
}

static int _phylist_valid_cb(struct nl_msg* msg, void* arg)
{

    int phyidx = 0;
    struct nlattr *tb[CTRL_ATTR_MAX + 1] = { 0 };
    struct nlmsghdr *nlhdr = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlhdr);

    // Parse all the attributes into the attribute table
    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    // Parse out PHY index
    phyidx = nla_get_u32(tb[NL80211_ATTR_WIPHY]);

    // Parse out attributes into caller's struct
    _nlattr2phyinfo(tb, &_phylist[phyidx]);

    return NL_OK;

}

static int _phylist_finish_cb(struct nl_msg* msg, void* arg)
{
    fprintf(stdout, "[%d] %s(%p, %p)\n", __LINE__, __FUNCTION__, msg, arg);
    return NL_STOP;
}

static int _phyinfo_valid_cb(struct nl_msg* msg, void* arg)
{

    WcapPhyInfo_t* info = (WcapPhyInfo_t*)arg;
    struct nlattr *tb[CTRL_ATTR_MAX + 1] = { 0 };
    struct nlmsghdr *nlhdr = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlhdr);

    // Parse all the attributes into the attribute table
    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    // Parse out attributes into caller's struct
    _nlattr2phyinfo(tb, info);

    return NL_OK;

}

static int _phyinfo_finish_cb(struct nl_msg* msg, void* arg)
{
    fprintf(stdout, "[%d] %s(%p, %p)\n", __LINE__, __FUNCTION__, msg, arg);
    return NL_STOP;
}

bool nl80211_phyinfo_dump(WcapPhyInfo_t** list)
{

    struct nl_msg* msg = NULL;

    if (list == NULL) return false;

    // Install callbacks
    if (!WcapGENLSetCallback(NL_CB_VALID, _phylist_valid_cb, list))
    {
        fprintf(stderr, "Cannot install valid callback\n");
        return false;
    }
    if (!WcapGENLSetCallback(NL_CB_FINISH, _phylist_finish_cb, list))
    {
        fprintf(stderr, "Cannot install finish callback\n");
        return false;
    }

    // Create 'get phy' command message
    msg = WcapGENLNewMsg(NL80211_GENL_NAME, NL80211_CMD_GET_WIPHY, NLM_F_DUMP);
    if (msg == NULL)
    {
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

    return true;
}

bool nl80211_phyinfo_get(const int phyindex, WcapPhyInfo_t* info)
{

    struct nl_msg* msg = NULL;

    // Initialized caller struct
    memset(info, 0, sizeof(*info));

    // Install callback
    if (!WcapGENLSetCallback(NL_CB_VALID, _phyinfo_valid_cb, info))
    {
        fprintf(stderr, "Cannot install callback: %d\n", phyindex);
        return false;
    }
    if (!WcapGENLSetCallback(NL_CB_FINISH, _phyinfo_finish_cb, info))
    {
        fprintf(stderr, "Cannot install callback: %d\n", phyindex);
        return false;
    }

    // Create 'get phy' command message
    msg = WcapNl80211NewMsg(NL80211_CMD_GET_WIPHY, 0);
    if (msg == NULL)
    {
        return false;
    }

    if (nla_put_u32(msg, NL80211_ATTR_WIPHY, phyindex) != 0)
    {
        fprintf(stderr, "Error adding phyindex\n");
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

    return true;

}

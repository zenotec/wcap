/*
 ============================================================================
 Name        : iface.c
 Author      : Kevin Mahoney <kevin.mahoney@zenotec.net>
 Version     :
 Copyright   : Your copyright notice
 Description : Wireless packet concatenator
 ============================================================================
 */

#include <stddef.h>

#include "iface.h"


bool WcapIfaceInfoGet(const char* ifname, WcapIfaceInfo_t* info)
{

    int err = 0;
    struct nl_cache* link_cache = NULL;
    struct nl_cache* addr_cache = NULL;
    struct rtnl_link* link = NULL;

    fprintf(stdout, "[%d] %s(%s, %p)\n", __LINE__, __FUNCTION__, ifname, info);

    if (!ifname || !info)
    {
        return false;
    }

    // Either choice, the result below is a mac address
    err = rtnl_link_alloc_cache(WcapRTNLSocket(), AF_UNSPEC, &link_cache);
    if (err != 0)
    {
        fprintf(stderr, "Failed to allocate link cache: %s\n", nl_geterror(err));
        return false;
    }

    link = rtnl_link_get_by_name(link_cache, ifname);
    if (link == NULL)
    {
        return false;
    }

    info->ifindex = rtnl_link_get_ifindex(link);
    strncpy(info->ifname, rtnl_link_get_name(link), sizeof(info->ifname));
    info->flags = rtnl_link_get_flags(link);
    info->opstate = rtnl_link_get_operstate(link);
    info->linkstate = rtnl_link_get_carrier(link);
    memcpy(info->hwaddr, nl_addr_get_binary_addr(rtnl_link_get_addr(link)), sizeof(info->hwaddr));
    info->mtu = rtnl_link_get_mtu(link);

    err = rtnl_addr_alloc_cache(WcapRTNLSocket(), &addr_cache);
    if (err != 0)
    {
        printf("Failed to allocate address cache: %s\n", nl_geterror(err));
        return false;
    }

    return true;
}

bool WcapIfaceInfoSet(const char* ifname, WcapIfaceInfo_t* info)
{

    int err = 0;
    struct nl_cache* link_cache = NULL;
    struct rtnl_link* orig = NULL;
    struct rtnl_link* link = NULL;
    struct nl_cache* addr_cache = NULL;
    struct rtnl_addr* addr = NULL;
    struct nl_addr* local = NULL;

    fprintf(stdout, "[%d] %s(%s, %p)\n", __LINE__, __FUNCTION__, ifname, info);

    if (!ifname || !info)
    {
        return false;
    }

    // Either choice, the result below is a mac address
    err = rtnl_link_alloc_cache(WcapRTNLSocket(), AF_UNSPEC, &link_cache);
    if (err != 0)
    {
        fprintf(stderr, "Failed to allocate link cache: %s\n", nl_geterror(err));
        return false;
    }

    orig = rtnl_link_get_by_name(link_cache, ifname);
    if (orig == NULL)
    {
        return false;
    }

    link = rtnl_link_alloc();
    if (link == NULL)
    {
        fprintf(stderr, "Failed to allocate new link\n");
        return false;
    }

    rtnl_link_set_flags(link, info->flags);
    rtnl_link_set_mtu(link, info->mtu);

    err = rtnl_link_change(WcapRTNLSocket(), orig, link, 0);
    if (err < 0)
    {
        fprintf(stderr, "Failed to modify link: %s\n", nl_geterror(err));
        return false;
    }

    return true;
}

bool WcapIfaceInetAddrAdd(const char *ifname, const char* addr)
{

    int err = 0;
    WcapIfaceInfo_t info = { 0 };
    struct rtnl_addr* rtaddr = NULL;
    struct nl_addr* local = NULL;

    fprintf(stdout, "[%d] %s(%s, %s)\n", __LINE__, __FUNCTION__, ifname, addr);

    if (!ifname || !addr)
    {
        return false;
    }

    // Verify the interface exits and retrieve info for it
    if (!WcapIfaceInfoGet(ifname, &info))
    {
        fprintf(stderr, "Failed to find interface: %s\n", ifname);
        return false;
    }

    // Allocate address structure
    rtaddr = rtnl_addr_alloc();
    if (rtaddr == NULL)
    {
        fprintf(stderr, "Failed to allocate address\n");
        return false;
    }

    rtnl_addr_set_ifindex(rtaddr, info.ifindex);

    err = nl_addr_parse (addr, AF_INET, &local);
    if(err != 0)
    {
        fprintf(stderr, "Failed to parse local address: %s\n", nl_geterror(err));
        return false;
    }

    err = rtnl_addr_set_local(rtaddr, local);
    if (err != 0)
    {
        fprintf(stderr, "Failed to set local address: %s\n", nl_geterror(err));
        return false;
    }

    err = rtnl_addr_add(WcapRTNLSocket(), rtaddr, 0);
    if (err != 0)
    {
        fprintf(stderr, "Failed to add address: %s\n", nl_geterror(err));
        return false;
    }

    rtnl_addr_put(rtaddr);

    return true;
}

bool WcapIfaceInetAddrRemove(const char *ifname, const char* addr)
{

    int err = 0;
    WcapIfaceInfo_t info = { 0 };
    struct rtnl_addr* rtaddr = NULL;
    struct nl_addr* local = NULL;

    fprintf(stdout, "[%d] %s(%s, %s)\n", __LINE__, __FUNCTION__, ifname, addr);

    if (!ifname || !addr)
    {
        return false;
    }

    // Verify the interface exits and retrieve info for it
    if (!WcapIfaceInfoGet(ifname, &info))
    {
        fprintf(stderr, "Failed to find interface: %s\n", ifname);
        return false;
    }

    // Allocate address structure
    rtaddr = rtnl_addr_alloc();
    if (rtaddr == NULL)
    {
        fprintf(stderr, "Failed to allocate address\n");
        return false;
    }

    rtnl_addr_set_ifindex(rtaddr, info.ifindex);

    err = nl_addr_parse (addr, AF_INET, &local);
    if(err != 0)
    {
        fprintf(stderr, "Failed to parse local address: %s\n", nl_geterror(err));
        return false;
    }

    err = rtnl_addr_set_local(rtaddr, local);
    if (err != 0)
    {
        fprintf(stderr, "Failed to set local address: %s\n", nl_geterror(err));
        return false;
    }

    err = rtnl_addr_delete(WcapRTNLSocket(), rtaddr, 0);
    if (err != 0)
    {
        fprintf(stderr, "Failed to add address: %s\n", nl_geterror(err));
        return false;
    }

    rtnl_addr_put(rtaddr);

    return true;

}

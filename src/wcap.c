/*
 ============================================================================
 Name        : wcap.c
 Author      : Kevin Mahoney <kevin.mahoney@zenotec.net>
 Version     :
 Copyright   : Your copyright notice
 Description : Wireless packet concatenator
 ============================================================================
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "nl80211.h"

#define WCAP_SERVER_ADDR    "169.254.0.1"

static struct wcap_ctx
{
    int rawSock;
    struct sockaddr_ll monAddr;
    int udpSock;
    struct sockaddr_in srcAddr;
    struct sockaddr_in dstAddr;
} gCtx = { 0 };

void usage(const char* name)
{
    fprintf(stdout, "Utility to capture wireless packets from a local wireless\n");
    fprintf(stdout, "  interface and forward over a LAN to another instance\n");
    fprintf(stdout, "  which injects them into local wireless interface\n\n");
    fprintf(stdout, "Usage: %s { [-h] [-a <address> ] -c | -s } WIFACE IFACE \n", name);
    fprintf(stdout, "\t-h                 \tDisplay usage\n");
    fprintf(stdout, "\t-c                 \tOperate in client mode\n");
    fprintf(stdout, "\t-s                 \tOperate in server mode\n");
    fprintf(stdout, "\t-a <address>       \tIP address to use\n");
}

bool do_server(const char* wiface, const char* iface, const char* addr)
{

    bool status = true;
    WcapWifaceInfo_t iface_info = { 0 };
    WcapWifaceInfo_t monitor_info = { 0 };

    fprintf(stdout, "[%d] %s()\n", __LINE__, __FUNCTION__);

    // Validity check arguments
    if ((wiface == NULL) || !strlen(wiface))
    {
        fprintf(stderr, "Invalid source interface name");
        return false;
    }
    if ((iface == NULL) || !strlen(iface))
    {
        fprintf(stderr, "Invalid destination interface name");
        return false;
    }

    // Connect netlink socket for mananaging network
    if (!WcapNl80211Connect())
    {
        fprintf(stderr, "Failed to connect netlink socket\n");
        status = false;
        return false;
    }

    // Retrieve information about src interface
    if (!nl80211_wiface_get(wiface, &iface_info) && !nl80211_wiface_get(iface, &iface_info))
    {
        fprintf(stderr, "Failed to find interface: %s\n", iface);
        status = false;
        goto exit_fail;
    }

    // Construct name of monitor interface based on PHY index of primary interface
    snprintf(monitor_info.ifname, IF_NAMESIZE, "mon%d", iface_info.phy.phyindex);

    // Query for monitor interface, create it if it does not exist
    if (!nl80211_wiface_get(monitor_info.ifname, &monitor_info))
    {
        monitor_info.phy = iface_info.phy;
        monitor_info.iftype = NL80211_IFTYPE_MONITOR;
        if (!nl80211_wiface_new(&monitor_info))
        {
            fprintf(stderr, "Failed to create monitor interface: %s\n", monitor_info.ifname);
            status = false;
            goto exit_fail;
        }
        if (!nl80211_wiface_get(monitor_info.ifname, &monitor_info))
        {
            fprintf(stderr, "Failed to retrieve monitor interface info: %s\n", monitor_info.ifname);
            status = false;
            goto exit_fail;
        }
    }

    // Open raw socket for sending / receiving on monitor interface
    gCtx.rawSock = socket(PF_PACKET, (SOCK_RAW | SOCK_NONBLOCK), htons(ETH_P_ALL));
    if (gCtx.rawSock == 0)
    {
        fprintf(stderr, "Failed to open raw socket on monitor interface: %s\n", monitor_info.ifname);
        status = false;
        goto exit_fail;
    }

    // Construct raw socket address of monitor interface
    gCtx.monAddr.sll_ifindex = monitor_info.ifindex;
    gCtx.monAddr.sll_family = AF_PACKET;
    gCtx.monAddr.sll_protocol = htons(ETH_P_ALL);
    gCtx.monAddr.sll_pkttype = PACKET_HOST;

    // Bind raw socket to monitor interface
    if (bind(gCtx.rawSock, (struct sockaddr*) &gCtx.monAddr, sizeof(gCtx.monAddr)) < 0)
    {
        fprintf(stderr, "Failed to bind socket to monitor interface: %s\n", monitor_info.ifname);
        status = false;
        goto exit_fail;
    }

exit_fail:

    if (gCtx.rawSock != 0)
    {
        close(gCtx.rawSock);
        gCtx.rawSock = 0;
    }

    WcapNl80211Disconnect();

    return status;


}

bool do_client(const char* src, const char* dst, const char* addr)
{
    fprintf(stdout, "[%d] %s()\n", __LINE__, __FUNCTION__);

    // Validity check arguments
    if ((src == NULL) || !strlen(src))
    {
        fprintf(stderr, "Invalid source interface name");
        return false;
    }
    if ((dst == NULL) || !strlen(dst))
    {
        fprintf(stderr, "Invalid destination interface name");
        return false;
    }

    return true;
}

int main(int argc, char** argv)
{

    char* progname = NULL;
    char c;
    bool sflag = false;
    bool cflag = false;
    char* addr = NULL;
    char* wiface = NULL;
    char* iface = NULL;

    // Set program name
    progname = basename(argv[0]);
    opterr = 0;

    // Validate number of arguments before attempting to parse command line
    if (argc <= 1)
    {
        usage(progname);
        goto exit_success;
    }

    // Parse command line arguments
    while ((c = getopt(argc, argv, "hsc:")) != -1)
    {
        switch (c)
        {
            case 'h':
            {
                usage(progname);
                goto exit_success;
            }
            case 's':
            {
                sflag = true;
                break;
            }
            case 'c':
            {
                cflag = true;
                addr = optarg;
                break;
            }
            case 'a':
            {
                break;
            }
            case '?':
            {
                if (optopt == 'c')
                {
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                }
                goto exit_fail;
            }
            default:
            {
                goto exit_fail;
            }
        }
    }

    // Validate command line arguments
    if (!(cflag || sflag))
    {
        fprintf(stderr, "Must specify mode\n");
        goto exit_fail;
    }
    else if (cflag && sflag)
    {
        fprintf(stderr, "Must specify only one mode\n");
        goto exit_fail;
    }

    wiface = argv[optind++];
    iface = argv[optind++];

    if (sflag)
    {
        return do_server(wiface, iface, addr);
    }

    else if (cflag)
    {
        return do_client(wiface, iface, addr);
    }

exit_fail:
    usage(progname);
    return EXIT_FAILURE;

exit_success:
    return EXIT_SUCCESS;
}

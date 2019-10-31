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
#include <poll.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "iface.h"
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

static bool do_server(const char* wiface, const char* iface)
{

    bool status = true;
    WcapIfaceInfo_t iface_info = { 0 };
    char addr[16] = { 0 };
    WcapWifaceInfo_t wiface_info = { 0 };
    WcapWifaceInfo_t monitor_info = { 0 };
    struct pollfd fds[2] = { 0 };
    int nfds = 0;

    errno = 0;

    // Validity check arguments
    if ((wiface == NULL) || !strlen(wiface))
    {
        fprintf(stderr, "Invalid wireless interface name");
        return false;
    }
    if ((iface == NULL) || !strlen(iface))
    {
        fprintf(stderr, "Invalid ethernet interface name");
        return false;
    }

    // Connect NL80211 netlink socket for managing wireless interfaces
    if (!WcapGENLConnect())
    {
        fprintf(stderr, "Failed to connect General netlink socket\n");
        return false;
    }

    // Connect Route netlink socket for managing ethernet interfaces
    if (!WcapRTNLConnect())
    {
        fprintf(stderr, "Failed to connect Route netlink socket\n");
        return false;
    }

    // Retrieve information about ethernet interface
    if (!WcapIfaceInfoGet(iface, &iface_info))
    {
        fprintf(stderr, "Failed to find interface: %s\n", iface);
        status = false;
        goto exit_fail;
    }

    fprintf(stdout, "Found ethernet interface: [%d] %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                    iface_info.ifindex, iface_info.ifname,
                    iface_info.hwaddr[0], iface_info.hwaddr[1], iface_info.hwaddr[2],
                    iface_info.hwaddr[3], iface_info.hwaddr[4], iface_info.hwaddr[5]);

    // Construct link local address using the last two octets of the interface's MAC
    snprintf(addr, 16, "169.254.%d.%d", iface_info.hwaddr[4], iface_info.hwaddr[5]);

    // Add address to interface
    if (!WcapIfaceInetAddrAdd(iface, addr))
    {
        fprintf(stdout, "Failed to add link local address to interface: %s\n", iface);
    }

    // Retrieve information about wireless interface
    if (!WcapNL80211WifaceGet(wiface, &wiface_info) && !WcapNL80211WifaceGet(wiface, &wiface_info))
    {
        fprintf(stderr, "Failed to find interface: %s\n", wiface);
        status = false;
        goto exit_fail;
    }

    fprintf(stdout, "Found wireless interface: [%d] %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                    wiface_info.ifindex, wiface_info.ifname,
                    wiface_info.iface.hwaddr[0], wiface_info.iface.hwaddr[1],
                    wiface_info.iface.hwaddr[2],
                    wiface_info.iface.hwaddr[3], wiface_info.iface.hwaddr[4],
                    wiface_info.iface.hwaddr[5]);

    // Construct name of monitor interface based on PHY index of primary interface
    snprintf(monitor_info.ifname, IF_NAMESIZE, "mon%d", wiface_info.phy.phyindex);

    // Query for monitor interface, create it if it does not exist
    if (!WcapNL80211WifaceGet(monitor_info.ifname, &monitor_info))
    {
        monitor_info.phy = wiface_info.phy;
        monitor_info.iftype = NL80211_IFTYPE_MONITOR;
        if (!WcapNL80211WifaceCreate(&monitor_info))
        {
            fprintf(stderr, "Failed to create monitor interface: %s\n", monitor_info.ifname);
            status = false;
            goto exit_fail;
        }
        if (!WcapNL80211WifaceGet(monitor_info.ifname, &monitor_info))
        {
            fprintf(stderr, "Failed to retrieve monitor interface info: %s\n", monitor_info.ifname);
            status = false;
            goto exit_fail;
        }
    }

    // Open raw socket for sending / receiving on monitor interface
    gCtx.rawSock = socket(AF_PACKET, (SOCK_RAW | SOCK_NONBLOCK), htons(ETH_P_ALL));
    if (gCtx.rawSock < 0)
    {
        fprintf(stderr, "Failed to open raw socket on monitor interface: %s\n",
                        monitor_info.ifname);
        status = false;
        goto exit_fail;
    }
    fprintf(stdout, "Opened socket [%d] for listening on monitor interface: %s\n", gCtx.rawSock,
                    monitor_info.ifname);

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

    // Open UDP socket for sending / receiving encapsulated 80211 frames
    gCtx.udpSock = socket(AF_INET, (SOCK_DGRAM | SOCK_NONBLOCK), 0);
    if (gCtx.udpSock < 0)
    {
        fprintf(stderr, "Failed to open UDP socket on Ethernet interface: %s\n", iface_info.ifname);
        status = false;
        goto exit_fail;
    }
    fprintf(stdout, "Opened socket [%d] for listening on Ethernet interface: %s\n", gCtx.udpSock,
                    iface_info.ifname);

    // Set up IP address for UDP socket
    gCtx.srcAddr.sin_family = AF_INET;
    gCtx.srcAddr.sin_addr.s_addr = inet_addr(addr);
    gCtx.srcAddr.sin_port = htons(8888);

    // Bind UDP socket to link local address
    if (bind(gCtx.udpSock, (struct sockaddr*) &gCtx.srcAddr, sizeof(gCtx.srcAddr)) < 0)
    {
        fprintf(stderr, "Failed to bind socket to monitor interface: %s\n", monitor_info.ifname);
        status = false;
        goto exit_fail;
    }

    // Set up to listen on both sockets
    nfds = 0;
    fds[nfds].fd = gCtx.rawSock;
    fds[nfds++].events = (POLLIN | POLLERR);
    fds[nfds].fd = gCtx.udpSock;
    fds[nfds++].events = (POLLIN | POLLERR);

    while (true)
    {
        printf("Waiting on poll(%d)...\n", nfds);
        if (poll(fds, nfds, 10000) < 0)
        {
            fprintf(stderr, "Polling error occurred\n");
            status = false;
            goto exit_del_addr;
        }
        for (int i = 0; i < nfds; i++)
        {
            if (fds[i].revents & POLLIN)
            {
                char buf[8192] = { 0 };
                fprintf(stdout, "Socket [%d] ready to receive\n", fds[i].fd);
                recvfrom(fds[i].fd, &buf, sizeof(buf), 0, NULL, 0);
                continue;
            }
            if (fds[i].revents & POLLERR)
            {
                fprintf(stderr, "Socket [%d] encountered an error: [%d] %s\n", fds[i].fd, errno,
                                strerror(errno));
                status = false;
                goto exit_del_addr;
            }
        }
    }

    exit_del_addr:

    if (!WcapIfaceInetAddrRemove(iface, addr))
    {
        fprintf(stdout, "Failed to remove link local address from interface: %s\n", iface);
    }

    exit_fail:

    if (gCtx.udpSock != 0)
    {
        close(gCtx.udpSock);
        gCtx.udpSock = 0;
    }

    if (gCtx.rawSock != 0)
    {
        close(gCtx.rawSock);
        gCtx.rawSock = 0;
    }

    WcapNL80211Disconnect();

    return status;

}

bool do_client(const char* wiface, const char* iface, const char* dst)
{

    bool status = true;
    WcapIfaceInfo_t iface_info = { 0 };
    char addr[16] = { 0 };
    WcapWifaceInfo_t wiface_info = { 0 };
    WcapWifaceInfo_t monitor_info = { 0 };
    struct pollfd fds[2] = { 0 };
    int nfds = 0;

    errno = 0;

    // Validity check arguments
    if ((wiface == NULL) || !strlen(wiface))
    {
        fprintf(stderr, "Invalid wireless interface name");
        return false;
    }
    if ((iface == NULL) || !strlen(iface))
    {
        fprintf(stderr, "Invalid ethernet interface name");
        return false;
    }

    // Connect NL80211 netlink socket for managing wireless interfaces
    if (!WcapGENLConnect())
    {
        fprintf(stderr, "Failed to connect General netlink socket\n");
        return false;
    }

    // Connect Route netlink socket for managing ethernet interfaces
    if (!WcapRTNLConnect())
    {
        fprintf(stderr, "Failed to connect Route netlink socket\n");
        return false;
    }

    // Retrieve information about ethernet interface
    if (!WcapIfaceInfoGet(iface, &iface_info))
    {
        fprintf(stderr, "Failed to find interface: %s\n", iface);
        status = false;
        goto exit_fail;
    }

    fprintf(stdout, "Found ethernet interface: [%d] %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                    iface_info.ifindex, iface_info.ifname,
                    iface_info.hwaddr[0], iface_info.hwaddr[1], iface_info.hwaddr[2],
                    iface_info.hwaddr[3], iface_info.hwaddr[4], iface_info.hwaddr[5]);

    // Construct link local address using the last two octets of the interface's MAC
    snprintf(addr, 16, "169.254.%d.%d", iface_info.hwaddr[4], iface_info.hwaddr[5]);

    // Add address to interface
    if (!WcapIfaceInetAddrAdd(iface, addr))
    {
        fprintf(stdout, "Failed to add link local address to interface: %s\n", iface);
    }

    // Retrieve information about wireless interface
    if (!WcapNL80211WifaceGet(wiface, &wiface_info) && !WcapNL80211WifaceGet(wiface, &wiface_info))
    {
        fprintf(stderr, "Failed to find interface: %s\n", wiface);
        status = false;
        goto exit_fail;
    }

    fprintf(stdout, "Found wireless interface: [%d] %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                    wiface_info.ifindex, wiface_info.ifname,
                    wiface_info.iface.hwaddr[0], wiface_info.iface.hwaddr[1],
                    wiface_info.iface.hwaddr[2],
                    wiface_info.iface.hwaddr[3], wiface_info.iface.hwaddr[4],
                    wiface_info.iface.hwaddr[5]);

    // Construct name of monitor interface based on PHY index of primary interface
    snprintf(monitor_info.ifname, IF_NAMESIZE, "mon%d", wiface_info.phy.phyindex);

    // Query for monitor interface, create it if it does not exist
    if (!WcapNL80211WifaceGet(monitor_info.ifname, &monitor_info))
    {
        monitor_info.phy = wiface_info.phy;
        monitor_info.iftype = NL80211_IFTYPE_MONITOR;
        if (!WcapNL80211WifaceCreate(&monitor_info))
        {
            fprintf(stderr, "Failed to create monitor interface: %s\n", monitor_info.ifname);
            status = false;
            goto exit_fail;
        }
        if (!WcapNL80211WifaceGet(monitor_info.ifname, &monitor_info))
        {
            fprintf(stderr, "Failed to retrieve monitor interface info: %s\n", monitor_info.ifname);
            status = false;
            goto exit_fail;
        }
    }

    // Open raw socket for sending / receiving on monitor interface
    gCtx.rawSock = socket(AF_PACKET, (SOCK_RAW | SOCK_NONBLOCK), htons(ETH_P_ALL));
    if (gCtx.rawSock < 0)
    {
        fprintf(stderr, "Failed to open raw socket on monitor interface: %s\n",
                        monitor_info.ifname);
        status = false;
        goto exit_fail;
    }
    fprintf(stdout, "Opened socket [%d] for listening on monitor interface: %s\n", gCtx.rawSock,
                    monitor_info.ifname);

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

    // Open UDP socket for sending / receiving encapsulated 80211 frames
    gCtx.udpSock = socket(AF_INET, (SOCK_DGRAM | SOCK_NONBLOCK), 0);
    if (gCtx.udpSock < 0)
    {
        fprintf(stderr, "Failed to open UDP socket on Ethernet interface: %s\n", iface_info.ifname);
        status = false;
        goto exit_fail;
    }
    fprintf(stdout, "Opened socket [%d] for listening on Ethernet interface: %s\n", gCtx.udpSock,
                    iface_info.ifname);

    // Set up IP address for UDP socket
    gCtx.srcAddr.sin_family = AF_INET;
    gCtx.srcAddr.sin_addr.s_addr = inet_addr(addr);
    gCtx.srcAddr.sin_port = htons(8888);

    // Bind UDP socket to link local address
    if (bind(gCtx.udpSock, (struct sockaddr*) &gCtx.srcAddr, sizeof(gCtx.srcAddr)) < 0)
    {
        fprintf(stderr, "Failed to bind socket to monitor interface: %s\n", monitor_info.ifname);
        status = false;
        goto exit_fail;
    }

    // Set up to listen on both sockets
    nfds = 0;
    fds[nfds].fd = gCtx.rawSock;
    fds[nfds++].events = (POLLIN | POLLERR);
    fds[nfds].fd = gCtx.udpSock;
    fds[nfds++].events = (POLLIN | POLLERR);

    while (true)
    {
        printf("Waiting on poll(%d)...\n", nfds);
        if (poll(fds, nfds, 10000) < 0)
        {
            fprintf(stderr, "Polling error occurred\n");
            status = false;
            goto exit_del_addr;
        }
        for (int i = 0; i < nfds; i++)
        {
            if (fds[i].revents & POLLIN)
            {
                char buf[8192] = { 0 };
                fprintf(stdout, "Socket [%d] ready to receive\n", fds[i].fd);
                recvfrom(fds[i].fd, &buf, sizeof(buf), 0, NULL, 0);
                continue;
            }
            if (fds[i].revents & POLLERR)
            {
                fprintf(stderr, "Socket [%d] encountered an error: [%d] %s\n", fds[i].fd, errno,
                                strerror(errno));
                status = false;
                goto exit_del_addr;
            }
        }
    }

    exit_del_addr:

    if (!WcapIfaceInetAddrRemove(iface, addr))
    {
        fprintf(stdout, "Failed to remove link local address from interface: %s\n", iface);
    }

    exit_fail:

    if (gCtx.udpSock != 0)
    {
        close(gCtx.udpSock);
        gCtx.udpSock = 0;
    }

    if (gCtx.rawSock != 0)
    {
        close(gCtx.rawSock);
        gCtx.rawSock = 0;
    }

    WcapNL80211Disconnect();

    return status;

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
        return do_server(wiface, iface);
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

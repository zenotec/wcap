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

static struct wcap_ctx
{
    int udpSock;
    int udpSockIdx;
    struct sockaddr_in udpAddr;
    int rawSock;
    int rawSockIdx;
    struct sockaddr_ll rawAddr;
    struct sockaddr_in dstAddr;
} gCtx = { 0 };

void usage(const char* name)
{
    fprintf(stdout, "Utility to capture wireless packets from a local wireless\n");
    fprintf(stdout, "  interface and forward over a LAN to another instance\n");
    fprintf(stdout, "  which injects them into local wireless interface\n\n");
    fprintf(stdout, "Usage: %s { [-h] -s | -c <address> } WIFACE IFACE \n", name);
    fprintf(stdout, "\t-h                 \tDisplay usage\n");
    fprintf(stdout, "\t-s                 \tOperate in server mode\n");
    fprintf(stdout, "\t-c <address>       \tOperate in client mode\n");
}

static bool do_server(const char* wiface, const char* iface)
{

    bool status = true;
    bool hwsim = true;
    WcapIfaceInfo_t iface_info = { 0 };
    char addr[16] = { 0 };
    WcapWifaceInfo_t wiface_info = { 0 };
    struct pollfd fds[2] = { 0 };
    int nfds = 0;

    errno = 0;

    // Validity check arguments
    if ((iface == NULL) || !strlen(iface))
    {
        fprintf(stderr, "Invalid ethernet interface name");
        return false;
    }
    if ((wiface == NULL) || !strlen(wiface))
    {
        fprintf(stderr, "Invalid wireless interface name");
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

    //-------------------------------------------------------------------------
    // Retrieve information about Ethernet interface
    //-------------------------------------------------------------------------

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
    if (!WcapIfaceInetAddrAdd(iface, addr, 16))
    {
        fprintf(stdout, "Failed to add link local address to interface: %s\n", iface);
    }

    // Set the interface's state to administratively up
    iface_info.flags |= (IFF_UP | IFF_RUNNING);
    if (!WcapIfaceInfoSet(iface, &iface_info))
    {
        fprintf(stderr, "Failed to bring interface '%s' up\n", iface);
        status = false;
        goto exit_del_addr;
    }

    // Open UDP socket for sending / receiving encapsulated 80211 frames
    gCtx.udpSock = socket(AF_INET, (SOCK_DGRAM | SOCK_NONBLOCK), 0);
    if (gCtx.udpSock < 0)
    {
        fprintf(stderr, "Failed to open UDP socket on Ethernet interface: %s\n", iface_info.ifname);
        status = false;
        goto exit_del_addr;
    }

    // Set up IP address for UDP socket
    gCtx.udpAddr.sin_family = AF_INET;
    gCtx.udpAddr.sin_addr.s_addr = inet_addr(addr);
    gCtx.udpAddr.sin_port = htons(8888);

    // Bind UDP socket to link local address
    if (bind(gCtx.udpSock, (struct sockaddr*) &gCtx.udpAddr, sizeof(gCtx.udpAddr)) < 0)
    {
        fprintf(stderr, "Failed to bind socket to monitor interface: %s\n", iface_info.ifname);
        status = false;
        goto exit_del_addr;
    }

    fprintf(stdout, "Listening on Ethernet interface: %s (%s)\n", iface, addr);

    //-------------------------------------------------------------------------
    // Retrieve information about wireless interface
    //-------------------------------------------------------------------------

    if (!WcapNL80211WifaceGet(wiface, &wiface_info))
    {
        fprintf(stderr, "Failed to find interface: %s\n", wiface);
        status = false;
        goto exit_del_addr;
    }

    fprintf(stdout, "Found wireless interface: [%d] %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                    wiface_info.ifindex, wiface_info.ifname,
                    wiface_info.iface.hwaddr[0], wiface_info.iface.hwaddr[1],
                    wiface_info.iface.hwaddr[2],
                    wiface_info.iface.hwaddr[3], wiface_info.iface.hwaddr[4],
                    wiface_info.iface.hwaddr[5]);

    // Set the monitor interface's state to administratively up
    wiface_info.iface.flags |= (IFF_UP | IFF_RUNNING);
    if (!WcapIfaceInfoSet(wiface, &wiface_info.iface))
    {
        fprintf(stderr, "Failed to bring interface '%s' up\n", iface);
        status = false;
        goto exit_del_addr;
    }

    // Open raw socket for sending / receiving on monitor interface
    gCtx.rawSock = socket(AF_PACKET, (SOCK_RAW | SOCK_NONBLOCK), htons(ETH_P_ALL));
    if (gCtx.rawSock < 0)
    {
        fprintf(stderr, "Failed to open raw socket on monitor interface: %s\n",
                        wiface_info.ifname);
        status = false;
        goto exit_del_addr;
    }

    // Construct raw socket address of monitor interface
    gCtx.rawAddr.sll_ifindex = wiface_info.ifindex;
    gCtx.rawAddr.sll_family = AF_PACKET;
    gCtx.rawAddr.sll_protocol = htons(ETH_P_ALL);
    gCtx.rawAddr.sll_pkttype = PACKET_HOST;

    // Bind raw socket to monitor interface
    if (bind(gCtx.rawSock, (struct sockaddr*) &gCtx.rawAddr, sizeof(gCtx.rawAddr)) < 0)
    {
        fprintf(stderr, "Failed to bind socket to monitor interface: %s\n", wiface_info.ifname);
        status = false;
        goto exit_del_addr;
    }

    fprintf(stdout, "Listening on Wireless interface: [%d] %s\n", wiface_info.ifindex, wiface_info.ifname);

    //-------------------------------------------------------------------------
    // Set up to listen on both sockets
    //-------------------------------------------------------------------------

    nfds = 0;

    gCtx.udpSockIdx = nfds++;
    fds[gCtx.udpSockIdx].fd = gCtx.udpSock;
    fds[gCtx.udpSockIdx].events = (POLLIN | POLLERR);

    gCtx.rawSockIdx = nfds++;
    fds[gCtx.rawSockIdx].fd = gCtx.rawSock;
    fds[gCtx.rawSockIdx].events = (POLLIN | POLLERR);

    while (true)
    {
        if (poll(fds, nfds, 10000) < 0)
        {
            fprintf(stderr, "Polling error occurred\n");
            status = false;
            goto exit_del_addr;
        }
        for (int i = 0; i < nfds; i++)
        {
            if (fds[i].revents & POLLERR)
            {
                fprintf(stderr, "Socket [%d] encountered an error: [%d] %s\n", fds[i].fd, errno,
                                strerror(errno));
                status = false;
                goto exit_del_addr;
            }
        }
        if (fds[gCtx.udpSockIdx].revents & POLLIN)
        {
            char buf[8192] = { 0 };
            int addrlen = sizeof(gCtx.dstAddr);
            int cnt = recvfrom(fds[gCtx.udpSockIdx].fd, &buf, sizeof(buf), 0, (struct sockaddr*) &gCtx.dstAddr, &addrlen);
            fprintf(stdout, "Received %d bytes on UDP socket: %d\n", cnt, fds[gCtx.udpSockIdx].fd);
            cnt = sendto(gCtx.rawSock, buf, cnt, 0, NULL, 0);
            fprintf(stdout, "Sent %d bytes on Raw socket: %d\n", cnt, fds[gCtx.rawSockIdx].fd);
        }
        if (fds[gCtx.rawSockIdx].revents & POLLIN)
        {
            char buf[8192] = { 0 };
            int cnt = recvfrom(fds[gCtx.rawSockIdx].fd, &buf, sizeof(buf), 0, NULL, NULL);
            fprintf(stdout, "Received %d bytes on Raw socket: %d\n", cnt, fds[gCtx.rawSockIdx].fd);
            if (gCtx.dstAddr.sin_addr.s_addr)
            {
                cnt = sendto(gCtx.udpSock, buf, cnt, 0, (struct sockaddr*) &gCtx.dstAddr, sizeof(gCtx.dstAddr));
                fprintf(stdout, "Sent %d bytes on UDP socket: %d\n", cnt, fds[gCtx.udpSockIdx].fd);
            }
        }
    }

exit_del_addr:

    if (!WcapIfaceInetAddrRemove(iface, addr, 16))
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
    if ((iface == NULL) || !strlen(iface))
    {
        fprintf(stderr, "Invalid ethernet interface name");
        return false;
    }
    if ((wiface == NULL) || !strlen(wiface))
    {
        fprintf(stderr, "Invalid wireless interface name");
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

    //-------------------------------------------------------------------------
    // Retrieve information about Ethernet interface
    //-------------------------------------------------------------------------

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
    fprintf(stdout, "Flags: 0x%08x\n", iface_info.flags);

    // Construct link local address using the last two octets of the interface's MAC
    snprintf(addr, 16, "169.254.%d.%d", iface_info.hwaddr[4], iface_info.hwaddr[5]);

    // Add address to interface
    if (!WcapIfaceInetAddrAdd(iface, addr, 16))
    {
        fprintf(stdout, "Failed to add link local address to interface: %s\n", iface);
    }

    // Set the interface's state to administratively up
    iface_info.flags |= (IFF_UP | IFF_RUNNING);
    if (!WcapIfaceInfoSet(iface, &iface_info))
    {
        fprintf(stderr, "Failed to bring interface '%s' up\n", iface);
        status = false;
        goto exit_del_addr;
    }

    // Open UDP socket for sending / receiving encapsulated 80211 frames
    gCtx.udpSock = socket(AF_INET, (SOCK_DGRAM | SOCK_NONBLOCK), 0);
    if (gCtx.udpSock < 0)
    {
        fprintf(stderr, "Failed to open UDP socket on Ethernet interface: %s\n", iface_info.ifname);
        status = false;
        goto exit_del_addr;
    }

    // Set up IP address for UDP socket
    gCtx.udpAddr.sin_family = AF_INET;
    gCtx.udpAddr.sin_addr.s_addr = inet_addr(addr);
    gCtx.udpAddr.sin_port = htons(8888);

    // Set up IP address of server
    gCtx.dstAddr.sin_family = AF_INET;
    gCtx.dstAddr.sin_addr.s_addr = inet_addr(dst);
    gCtx.dstAddr.sin_port = htons(8888);

    // Bind UDP socket to link local address
    if (bind(gCtx.udpSock, (struct sockaddr*) &gCtx.udpAddr, sizeof(gCtx.udpAddr)) < 0)
    {
        fprintf(stderr, "Failed to bind socket to monitor interface: %s\n", monitor_info.ifname);
        status = false;
        goto exit_del_addr;
    }

    fprintf(stdout, "Listening on Ethernet interface: %s (%s)\n", iface, addr);

    //-------------------------------------------------------------------------
    // Retrieve information about wireless interface
    //-------------------------------------------------------------------------

    if (!WcapNL80211WifaceGet(wiface, &wiface_info))
    {
        fprintf(stderr, "Failed to find interface: %s\n", wiface);
        status = false;
        goto exit_del_addr;
    }

    fprintf(stdout, "Found wireless interface: [%d] %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                    wiface_info.ifindex, wiface_info.ifname,
                    wiface_info.iface.hwaddr[0], wiface_info.iface.hwaddr[1],
                    wiface_info.iface.hwaddr[2],
                    wiface_info.iface.hwaddr[3], wiface_info.iface.hwaddr[4],
                    wiface_info.iface.hwaddr[5]);

    // Set the monitor interface's state to administratively up
    wiface_info.iface.flags |= (IFF_UP | IFF_RUNNING);
    if (!WcapIfaceInfoSet(wiface, &wiface_info.iface))
    {
        fprintf(stderr, "Failed to bring interface '%s' up\n", iface);
        status = false;
        goto exit_del_addr;
    }

    // Open raw socket for sending / receiving on monitor interface
    gCtx.rawSock = socket(AF_PACKET, (SOCK_RAW | SOCK_NONBLOCK), htons(ETH_P_ALL));
    if (gCtx.rawSock < 0)
    {
        fprintf(stderr, "Failed to open raw socket on monitor interface: %s\n",
                        wiface_info.ifname);
        status = false;
        goto exit_del_addr;
    }

    // Construct raw socket address of monitor interface
    gCtx.rawAddr.sll_ifindex = wiface_info.ifindex;
    gCtx.rawAddr.sll_family = AF_PACKET;
    gCtx.rawAddr.sll_protocol = htons(ETH_P_ALL);
    gCtx.rawAddr.sll_pkttype = PACKET_HOST;

    // Bind raw socket to monitor interface
    if (bind(gCtx.rawSock, (struct sockaddr*) &gCtx.rawAddr, sizeof(gCtx.rawAddr)) < 0)
    {
        fprintf(stderr, "Failed to bind socket to monitor interface: %s\n", wiface_info.ifname);
        status = false;
        goto exit_del_addr;
    }

    fprintf(stdout, "Listening on Wireless interface: [%d] %s\n", wiface_info.ifindex, wiface_info.ifname);

    //-------------------------------------------------------------------------
    // Set up to listen on both sockets
    //-------------------------------------------------------------------------

    nfds = 0;

    gCtx.udpSockIdx = nfds++;
    fds[gCtx.udpSockIdx].fd = gCtx.udpSock;
    fds[gCtx.udpSockIdx].events = (POLLIN | POLLERR);

    gCtx.rawSockIdx = nfds++;
    fds[gCtx.rawSockIdx].fd = gCtx.rawSock;
    fds[gCtx.rawSockIdx].events = (POLLIN | POLLERR);

    while (true)
    {
        if (poll(fds, nfds, 10000) < 0)
        {
            fprintf(stderr, "Polling error occurred\n");
            status = false;
            goto exit_del_addr;
        }
        for (int i = 0; i < nfds; i++)
        {
            if (fds[i].revents & POLLERR)
            {
                fprintf(stderr, "Socket [%d] encountered an error: [%d] %s\n", fds[i].fd, errno,
                                strerror(errno));
                status = false;
                goto exit_del_addr;
            }
        }
        if (fds[gCtx.udpSockIdx].revents & POLLIN)
        {
            char buf[8192] = { 0 };
            int addrlen = sizeof(gCtx.dstAddr);
            int cnt = recvfrom(fds[gCtx.udpSockIdx].fd, &buf, sizeof(buf), 0, (struct sockaddr*) &gCtx.dstAddr, &addrlen);
            fprintf(stdout, "Received %d bytes on UDP socket: %d\n", cnt, fds[gCtx.udpSockIdx].fd);
            cnt = sendto(gCtx.rawSock, buf, cnt, 0, NULL, 0);
            fprintf(stdout, "Sent %d bytes on Raw socket: %d\n", cnt, fds[gCtx.rawSockIdx].fd);
        }
        if (fds[gCtx.rawSockIdx].revents & POLLIN)
        {
            char buf[8192] = { 0 };
            int cnt = recvfrom(fds[gCtx.rawSockIdx].fd, &buf, sizeof(buf), 0, NULL, NULL);
            fprintf(stdout, "Received %d bytes on Raw socket: %d\n", cnt, fds[gCtx.rawSockIdx].fd);
            cnt = sendto(gCtx.udpSock, buf, cnt, 0, (struct sockaddr*) &gCtx.dstAddr, sizeof(gCtx.dstAddr));
            fprintf(stdout, "Sent %d bytes on UDP socket [%d] to %s:%d\n", cnt, fds[gCtx.udpSockIdx].fd, inet_ntoa(gCtx.dstAddr.sin_addr), ntohs(gCtx.dstAddr.sin_port));
        }
    }

exit_del_addr:

    if (!WcapIfaceInetAddrRemove(iface, addr, 16))
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

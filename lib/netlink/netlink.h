/*
 ============================================================================
 Name        : netlink.h
 Author      : Kevin Mahoney <kevin.mahoney@zenotec.net>
 Version     :
 Copyright   : Your copyright notice
 Description : Wireless packet capture and forwarder
 ============================================================================
 */

#ifndef _NETLINK_H_
#define _NETLINK_H_

#include <stdbool.h>
#include <stdint.h>

#include <linux/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <netlink/msg.h>
#include <netlink/handlers.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>


bool WcapNetlinkConnect(const uint8_t proto);
bool WcapNetlinkDisconnect(const uint8_t proto);
struct nl_sock* WcapNetlinkSocket(const uint8_t proto);

bool WcapNetlinkSetCallback(const uint8_t proto, const enum nl_cb_type type, void* cb, void* arg);
bool WcapNetlinkClrCallback(const uint8_t proto, const enum nl_cb_type type);

struct nl_msg* WcapNetlinkNewMsg();
bool WcapNetlinkSendMsg(const uint8_t proto, struct nl_msg* msg);
bool WcapNetlinkRecvMsg(const uint8_t proto);

// Netlink General wrappers

bool WcapGENLConnect();
bool WcapGENLDisconnect();
struct nl_sock* WcapGENLSocket();

bool WcapGENLSetCallback(const enum nl_cb_type type, void* cb, void* arg);
bool WcapGENLClrCallback(const enum nl_cb_type type);

struct nl_msg* WcapGENLNewMsg(const char* fam, const int cmd, const int flags);
bool WcapGENLSendMsg(struct nl_msg* msg);
bool WcapGENLRecvMsg();

// Netlink Route wrappers

bool WcapRTNLConnect();
bool WcapRTNLDisconnect();
struct nl_sock* WcapRTNLSocket();

#endif /* _NETLINK_H_ */


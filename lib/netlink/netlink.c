/*
 ============================================================================
 Name        : netlink.c
 Author      : Kevin Mahoney <kevin.mahoney@zenotec.net>
 Version     :
 Copyright   : Your copyright notice
 Description : Wireless packet concatenator
 ============================================================================
 */

#include <unistd.h>

#include "netlink.h"

struct _nlcb
{
    bool done;
    bool err;
    nl_recvmsg_msg_cb_t seqchk;
    void* seqchk_arg;
    nl_recvmsg_msg_cb_t valid;
    void* valid_arg;
    nl_recvmsg_msg_cb_t finish;
    void* finish_arg;
    nl_recvmsg_msg_cb_t ack;
    void* ack_arg;
};

static struct nl_ctx
{
    struct nl_sock* sock;
    struct _nlcb cb;
} nlCtx[MAX_LINKS] = { 0 };

static int _nlseqchk_cb(struct nl_msg* msg, void* arg)
{
    int ret = NL_OK;
    struct nl_ctx* ctx = (struct nl_ctx*)arg;
    if (ctx->cb.seqchk)
    {
        ret = ctx->cb.seqchk(msg, ctx->cb.seqchk_arg);
    }
    return ret;
}

static int _nlvalid_cb(struct nl_msg* msg, void* arg)
{
    int ret = NL_OK;
    struct nl_ctx* ctx = (struct nl_ctx*)arg;
    if (ctx->cb.valid)
    {
        ret = ctx->cb.valid(msg, ctx->cb.valid_arg);
    }
    return ret;
}

static int _nlfinish_cb(struct nl_msg* msg, void* arg)
{
    int ret = NL_OK;
    struct nl_ctx* ctx = (struct nl_ctx*)arg;
    if (ctx->cb.finish)
    {
        ret = ctx->cb.finish(msg, ctx->cb.finish_arg);
    }
    ctx->cb.done = true;
    return ret;
}

static int _nlack_cb(struct nl_msg* msg, void* arg)
{
    int ret = NL_OK;
    struct nl_ctx* ctx = (struct nl_ctx*)arg;
    if (ctx->cb.ack)
    {
        ret = ctx->cb.ack(msg, ctx->cb.ack_arg);
    }
    ctx->cb.done = true;
    return ret;
}

static int _nlerr_cb(struct sockaddr_nl* nla, struct nlmsgerr* nlerr, void* arg)
{
    struct nl_ctx* ctx = (struct nl_ctx*)arg;
    fprintf(stdout, "[%d] %s(%p, %p, %p)\n", __LINE__, __FUNCTION__, nla, nlerr, arg);
    fprintf(stderr, "Netlink error: [%d] %s\n", nlerr->error, nl_geterror(nlerr->error));
    ctx->cb.err = true;
    return NL_OK;
}

//*****************************************************************************

bool WcapNetlinkConnect(const uint8_t proto)
{
    int ret = 0;

    if (proto >= MAX_LINKS)
        return false;

    if (nlCtx[proto].sock)
        return true;

    // Initialize context
    memset(&nlCtx[proto], 0, sizeof(nlCtx[proto]));

    // Allocate netlink socket resources
    nlCtx[proto].sock = nl_socket_alloc();
    if (nlCtx[proto].sock == NULL)
    {
        fprintf(stderr, "Error allocating netlink resources\n");
        return false;
    }

    // Connect netlink socket
    ret = nl_connect(nlCtx[proto].sock, proto);
    if (ret < 0)
    {
        fprintf(stderr, "Error connecting netlink socket: [%d] %s\n", ret, nl_geterror(ret));
        WcapNetlinkDisconnect(proto);
        return false;
    }

    // Install default callback routines
    ret = nl_socket_modify_cb(nlCtx[proto].sock, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, _nlseqchk_cb, &nlCtx[proto]);
    if (ret < 0)
    {
        fprintf(stderr, "Error installing sequence check callback: [%d] %s\n", ret, nl_geterror(ret));
        WcapNetlinkDisconnect(proto);
        return false;
    }

    ret = nl_socket_modify_cb(nlCtx[proto].sock, NL_CB_VALID, NL_CB_CUSTOM, _nlvalid_cb, &nlCtx[proto]);
    if (ret < 0)
    {
        fprintf(stderr, "Error installing valid callback: [%d] %s\n", ret, nl_geterror(ret));
        WcapNetlinkDisconnect(proto);
        return false;
    }

    ret = nl_socket_modify_cb(nlCtx[proto].sock, NL_CB_FINISH, NL_CB_CUSTOM, _nlfinish_cb, &nlCtx[proto]);
    if (ret < 0)
    {
        fprintf(stderr, "Error installing finish callback: [%d] %s\n", ret, nl_geterror(ret));
        WcapNetlinkDisconnect(proto);
        return false;
    }

    ret = nl_socket_modify_cb(nlCtx[proto].sock, NL_CB_ACK, NL_CB_CUSTOM, _nlack_cb, &nlCtx[proto]);
    if (ret < 0)
    {
        fprintf(stderr, "Error installing acknowledge callback: [%d] %s\n", ret, nl_geterror(ret));
        WcapNetlinkDisconnect(proto);
        return false;
    }

    ret = nl_socket_modify_err_cb(nlCtx[proto].sock, NL_CB_CUSTOM, _nlerr_cb, &nlCtx[proto]);
    if (ret < 0)
    {
        fprintf(stderr, "Error installing error callback: [%d] %s\n", ret, nl_geterror(ret));
        WcapNetlinkDisconnect(proto);
        return false;
    }

    return true;
}

bool WcapNetlinkDisconnect(const uint8_t proto)
{

    if (proto >= MAX_LINKS)
        return false;

    if (nlCtx[proto].sock)
    {
        nl_socket_free(nlCtx[proto].sock);
        memset(&nlCtx[proto], 0, sizeof(nlCtx[proto]));
    }

    return true;
}

bool WcapNetlinkSetCallback(const uint8_t proto, const enum nl_cb_type type, void* cb, void* arg)
{
    bool status = true;

    if (proto >= MAX_LINKS)
        return false;

    switch (type)
    {
        case NL_CB_SEQ_CHECK:
        {
            nlCtx[proto].cb.seqchk = cb;
            nlCtx[proto].cb.seqchk_arg = arg;
            break;
        }
        case NL_CB_VALID:
        {
            nlCtx[proto].cb.valid = cb;
            nlCtx[proto].cb.valid_arg = arg;
            break;
        }
        case NL_CB_FINISH:
        {
            nlCtx[proto].cb.finish = cb;
            nlCtx[proto].cb.finish_arg = arg;
            break;
        }
        case NL_CB_ACK:
        {
            nlCtx[proto].cb.ack = cb;
            nlCtx[proto].cb.ack_arg = arg;
            break;
        }
        default:
        {
            status = false;
            break;
        }
    }
    return status;
}

bool WcapNetlinkClrCallback(const uint8_t proto, const enum nl_cb_type type)
{
    bool status = true;

    if (proto >= MAX_LINKS)
        return false;

    // Set default callback based on type
    switch (type)
    {
        case NL_CB_SEQ_CHECK:
        {
            nlCtx[proto].cb.seqchk = NULL;
            nlCtx[proto].cb.seqchk_arg = NULL;
            break;
        }
        case NL_CB_VALID:
        {
            nlCtx[proto].cb.valid = NULL;
            nlCtx[proto].cb.valid_arg = NULL;
            break;
        }
        case NL_CB_FINISH:
        {
            nlCtx[proto].cb.finish = NULL;
            nlCtx[proto].cb.finish_arg = NULL;
            break;
        }
        case NL_CB_ACK:
        {
            nlCtx[proto].cb.ack = NULL;
            nlCtx[proto].cb.ack_arg = NULL;
            break;
        }
        default:
        {
            status = false;
            break;
        }
    }

    return status;
}

struct nl_msg* WcapNetlinkNewMsg()
{
    return nlmsg_alloc();
}

// Send a netlink message. Caller is responsible for allocating / freeing message
bool WcapNetlinkSendMsg(const uint8_t proto, struct nl_msg* msg)
{
    int ret = 0;

    if (proto >= MAX_LINKS)
        return false;

    // Send message and verify success
    ret = nl_send_auto(nlCtx[proto].sock, msg);
    if (ret < 0)
    {
        fprintf(stderr, "Error sending netlink message: [%d] %s\n", ret, nl_geterror(ret));
        return false;
    }

    nlmsg_free(msg);

    return true;

}

// Trigger receiving pending messages (note: Invokes installed callback)
bool WcapNetlinkRecvMsg(const uint8_t proto)
{
    int retries = 10;

    if (proto >= MAX_LINKS)
        return false;

    nlCtx[proto].cb.done = false;
    nlCtx[proto].cb.err = false;

    while (!nlCtx[proto].cb.done && !nlCtx[proto].cb.err && retries--)
    {
        int ret = nl_recvmsgs_default(nlCtx[proto].sock);
        if (ret < 0)
        {
            fprintf(stderr, "Error receiving netlink messages: [%d] %s\n", ret, nl_geterror(ret));
            return false;
        }
    }

    return true;

}
bool WcapGENLConnect()
{
    return WcapNetlinkConnect(NETLINK_GENERIC);
}

bool WcapGENLDisconnect()
{
    return WcapNetlinkDisconnect(NETLINK_GENERIC);
}

bool WcapGENLSetCallback(const enum nl_cb_type type, void* cb, void* arg)
{
    return WcapNetlinkSetCallback(NETLINK_GENERIC, type, cb, arg);
}

bool WcapGENLClrCallback(const enum nl_cb_type type)
{
    return WcapNetlinkClrCallback(NETLINK_GENERIC, type);
}

struct nl_msg* WcapGENLNewMsg(const char* fam, const int cmd, const int flags)
{
    int famid = 0;
    struct nl_msg* msg = WcapNetlinkNewMsg();
    if (msg == NULL)
    {
        fprintf(stderr, "Error allocating netlink message\n");
        return NULL;
    }

    // Query for family id
    famid = genl_ctrl_resolve(nlCtx[NETLINK_GENERIC].sock, fam);
    if (famid < 0)
    {
        fprintf(stderr, "Error resolving generic netlink family name: %s\n", fam);
        fprintf(stderr, "Error: [%d] %s\n", famid, nl_geterror(famid));
        WcapGENLDisconnect();
        return NULL;
    }

    // Initialize general message header
    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, famid, 0, flags, cmd, 0))
    {
        fprintf(stderr, "Error initializing netlink generic message header\n");
        WcapGENLDisconnect();
        return NULL;
    }

    return msg;
}

bool WcapGENLSendMsg(struct nl_msg* msg)
{
    return WcapNetlinkSendMsg(NETLINK_GENERIC, msg);
}

bool WcapGENLRecvMsg()
{
    return WcapNetlinkRecvMsg(NETLINK_GENERIC);
}

/*
 *
 * Copyright (C) 2019-2025, Broadband Forum
 * Copyright (C) 2024-2025, Vantiva Technologies SAS
 * Copyright (C) 2007-2024  CommScope, Inc
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * @file nu_ipaddr.c
 *
 * Implements a class that wraps IPv4/v6 address functionality
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h> // for getaddrinfo()
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include "common_defs.h"
#include "nu_ipaddr.h"
#include "usp_api.h"
#include "data_model.h"
#include "nu_macaddr.h"
#include "device.h"


#ifndef EFAIL
#define EFAIL EINVAL
#endif
#ifndef EMISMATCH
#define EMISMATCH EINVAL
#endif

#ifndef IN6ADDR_LINKLOCAL_ALLNODES_INIT
#define IN6ADDR_LINKLOCAL_ALLNODES_INIT \
    {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#endif

  // Macro to check if an IPv6 address is not globally routable
#define NOT_GLOBAL_UNICAST(addr) \
    (IN6_IS_ADDR_UNSPECIFIED(addr) || IN6_IS_ADDR_LOOPBACK(addr) || \
     IN6_IS_ADDR_MULTICAST(addr) || IN6_IS_ADDR_LINKLOCAL(addr) || \
     IN6_IS_ADDR_SITELOCAL(addr))


//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
int tw_ulib_get_dev_ipaddr(const char *dev, char *addr, size_t asiz, bool prefer_ipv6);

/*********************************************************************//**
**
**  nu_ipaddr_get_family
**
**  Returns the address family stored in the specified nu_ipaddr_t
**
** \param   addr - IP address to determine the address family of
** \param   familyp - pointer to variable in which to return the address family
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
nu_ipaddr_get_family(const nu_ipaddr_t *addr, sa_family_t *familyp)
{
    if (addr == NULL || familyp == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

#if IPV6_NUIPADDR
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        *familyp = AF_INET;
    } else {
        *familyp = AF_INET6;
    }
#else
    *familyp = AF_INET;
#endif
    return USP_ERR_OK;
}


/*********************************************************************//**
**
**  nu_ipaddr_to_inaddr
**
**  Converts the specified nu_ipaddr_t to an IPv4 in_addr structure
**  NOTE: The conversion may fail, if the specified nu_ipaddr_t contains an IPv6 address
**
** \param   addr - IP address to convert to an IPv4 in_addr structure
** \param   p - pointer to structure in which to return IPv4 in_addr
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
nu_ipaddr_to_inaddr(const nu_ipaddr_t *addr, struct in_addr *p)
{
    if (addr == NULL || p == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

#if IPV6_NUIPADDR
    if (IN6_IS_ADDR_V4MAPPED(addr) || IN6_IS_ADDR_V4COMPAT(addr)) {
        // Extract the IPv4 address from the last 4 bytes of the IPv6 address
        memcpy(&p->s_addr, &addr->s6_addr[12], sizeof(p->s_addr));
        return USP_ERR_OK;
    }

    USP_ERR_SetMessage("%s: Cannot convert IPv6 address to IPv4", __FUNCTION__);
    return USP_ERR_INTERNAL_ERROR;
#else
    p->s_addr = addr->s_addr;
    return USP_ERR_OK;
#endif
}

/*********************************************************************//**
**
**  nu_ipaddr_to_in6addr
**
**  Converts the specified nu_ipaddr_t to an IPv6 in6_addr structure
**  NOTE: The conversion may fail, if the specified nu_ipaddr_t contains an IPv4 address
**
** \param   addr - IP address to convert to an IPv6 in_addr structure
** \param   p - pointer to structure in which to return IPv6 in6_addr
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
nu_ipaddr_to_in6addr(const nu_ipaddr_t *addr, struct in6_addr *p)
{
    if (addr == NULL || p == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

#if IPV6_NUIPADDR
    if (IN6_IS_ADDR_V4MAPPED(addr) || IN6_IS_ADDR_V4COMPAT(addr)) {
        USP_ERR_SetMessage("%s: Cannot convert IPv4 address to IPv6", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }
    memcpy(p, addr, sizeof(struct in6_addr));
#else
    // Convert IPv4 to IPv4-mapped IPv6 address (::ffff:x.y.z.w)
    memset(p, 0, sizeof(struct in6_addr));
    p->s6_addr[10] = 0xff;
    p->s6_addr[11] = 0xff;
    memcpy(&p->s6_addr[12], &addr->s_addr, sizeof(addr->s_addr));
#endif
    return USP_ERR_OK;
}

/*********************************************************************//**
**
**  nu_ipaddr_to_sockaddr
**
**  Converts the specified nu_ipaddr_t to a sockaddr (which may contain either an IPv4 or IPv6 address, and a port)
**
** \param   addr - IP address to convert to a sockaddr
** \param   port - Port number to place in sockaddr structure
** \param   sa - pointer to structure in which to return sockaddr
** \param   len_p - pointer to variable in which to return the length of the sockaddr structure.
**                  NOTE: This may be specified as NULL, if the length is not required
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
nu_ipaddr_to_sockaddr(const nu_ipaddr_t *addr, int port, struct sockaddr_storage *sa, socklen_t *len_p)
{
    if (addr == NULL || sa == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    sa_family_t family;
    int err = nu_ipaddr_get_family(addr, &family);
    if (err != USP_ERR_OK) {
        return err;
    }

    memset(sa, 0, sizeof(*sa));

    if (family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        err = nu_ipaddr_to_in6addr(addr, &sin6->sin6_addr);
        if (err != USP_ERR_OK) {
            return err;
        }

        if (len_p != NULL) {
            *len_p = sizeof(struct sockaddr_in6);
        }
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        err = nu_ipaddr_to_inaddr(addr, &sin->sin_addr);
        if (err != USP_ERR_OK) {
            return err;
        }

        if (len_p != NULL) {
            *len_p = sizeof(struct sockaddr_in);
        }
    }

    return USP_ERR_OK;
}


/*********************************************************************//**
**
**  nu_ipaddr_to_str
**
**  Converts the specified nu_ipaddr_t into a string format IP address
**
** \param   addr - IP address to convert to a string
** \param   buf - pointer to buffer in which to return the string
** \param   bufsiz - size of buffer in which to return the string. This must be at least NU_IPADDRSTRLEN bytes long.
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
nu_ipaddr_to_str(const nu_ipaddr_t *addr, char *buf, int buflen)
{
    if (addr == NULL || buf == NULL || buflen < NU_IPADDRSTRLEN) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    buf[0] = '\0'; // Initialize buffer to empty string

#if IPV6_NUIPADDR
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        // Extract IPv4 address from IPv4-mapped IPv6 address
        const char *cp = inet_ntop(AF_INET, &addr->s6_addr[12], buf, buflen);
        if (cp == NULL) {
            USP_ERR_ERRNO("inet_ntop", errno);
            return USP_ERR_INTERNAL_ERROR;
        }
        return USP_ERR_OK;
    }
    // Handle pure IPv6 address
    const char *cp = inet_ntop(AF_INET6, addr, buf, buflen);
#else
    const char *cp = inet_ntop(AF_INET, addr, buf, buflen);
#endif
    if (cp == NULL) {
        USP_ERR_ERRNO("inet_ntop", errno);
        return USP_ERR_INTERNAL_ERROR;
    }
    return USP_ERR_OK;
}


/*********************************************************************//**
**
**  nu_ipaddr_str
**
**  Convenience function for logging, which always returns a string, given the specified nu_ipaddr_t
**
** \param   addr - IP address to convert to a string
** \param   buf - pointer to buffer in which to return the string
** \param   bufsiz - size of buffer in which to return the string. This must be at least NU_IPADDRSTRLEN bytes long.
**
** \return  buf if successfully converted, 'UNKNOWN' otherwise
**
**************************************************************************/
char *nu_ipaddr_str(const nu_ipaddr_t *addr, char *buf, int buflen)
{
    if (nu_ipaddr_to_str(addr, buf, buflen) != USP_ERR_OK) {
        strncpy(buf, "UNKNOWN", buflen);
        buf[buflen - 1] = '\0';
    }
    return buf;
}


/*********************************************************************//**
**
**  nu_ipaddr_from_str
**
**  Converts the specified IP Address string into a nu_ipaddr_t
**
** \param   str - pointer to string containing IP Address to convert
** \param   addr - pointer to structure in which to return the nu_ipaddr_t
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
nu_ipaddr_from_str(const char *str, nu_ipaddr_t *addr)
{
    if (str == NULL || addr == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    const char *p = str;
    char buf[64];
    int i = 0;

    // Skip leading whitespace
    while (*p != '\0' && isspace((unsigned char)*p)) {
        p++;
    }

    // Handle IPv6 address in brackets
    if (*p == '[') {
        p++;
        for (i = 0; *p && i < sizeof(buf) - 1; i++, p++) {
            if (*p == ']') {
                buf[i] = '\0';
                break;
            }
            buf[i] = *p;
        }
        if (i >= sizeof(buf) - 1) {
            USP_ERR_SetMessage("%s: IPv6 address too long", __FUNCTION__);
            return USP_ERR_INTERNAL_ERROR;
        }
        p = buf;
    } else {
        p = str;
    }

    // Determine address family
    sa_family_t family = AF_INET;
    struct in_addr in4;
    struct in6_addr in6;
    void *inptr = &in4;

#if IPV6_NUIPADDR
    for (const char *q = p; *q != '\0'; q++) {
        if (*q == ':' || isxdigit((unsigned char)*q)) {
            family = AF_INET6;
            inptr = &in6;
            break;
        }
        if (*q != '.' && !isdigit((unsigned char)*q)) {
            break;
        }
    }
#endif

    if (inet_pton(family, p, inptr) != 1) {
        USP_ERR_SetMessage("%s: inet_pton failed for %s", __FUNCTION__, p);
        return USP_ERR_INTERNAL_ERROR;
    }

    int err;
    if (family == AF_INET) {
        err = nu_ipaddr_from_inaddr(&in4, addr);
    } else {
        err = nu_ipaddr_from_in6addr(&in6, addr);
    }

    return err;
}


/*********************************************************************//**
**
**  nu_ipaddr_from_sockaddr_storage
**
**  Converts a sockaddr_storage structure to a nu_ipaddr_t structure and (optionally) a port
**
** \param   p - pointer to sockaddr_storage structure to convert to a nu_ipaddr_t.
** \param   addr - pointer to structure in which to return the nu_ipaddr_t
** \param   port - pointer to variable in which to return the IP port, or NULL, if this is not required
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INTERNAL_ERROR if address family was not supported.
**          NOTE: This function may be called with unsupported address families. The caller must handle this.
**
**************************************************************************/
int
nu_ipaddr_from_sockaddr_storage(const struct sockaddr_storage *p, nu_ipaddr_t *addr, uint16_t *port)
{
    if (p == NULL || addr == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    int err;
    if (p->ss_family == AF_INET) {
        struct sockaddr_in *sin4 = (struct sockaddr_in *)p;
        err = nu_ipaddr_from_inaddr(&sin4->sin_addr, addr);
        if (err == USP_ERR_OK && port != NULL) {
            *port = ntohs(sin4->sin_port);
        }
    } else if (p->ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)p;
        err = nu_ipaddr_from_in6addr(&sin6->sin6_addr, addr);
        if (err == USP_ERR_OK && port != NULL) {
            *port = ntohs(sin6->sin6_port);
        }
    } else {
        USP_ERR_SetMessage("%s: Unsupported address family %d", __FUNCTION__, p->ss_family);
        return USP_ERR_INTERNAL_ERROR;
    }

    return err;
}

/*********************************************************************//**
**
**  nu_ipaddr_from_inaddr
**
**  Converts an (IPv4) in_addr structure to a nu_ipaddr_t structure
**
** \param   p - pointer to in_addr structure to convert to a nu_ipaddr_t. NOTE: in_addr structures are always in network byte order
** \param   addr - pointer to structure in which to return the nu_ipaddr_t
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
nu_ipaddr_from_inaddr(const struct in_addr *p, nu_ipaddr_t *addr)
{
    if (p == NULL || addr == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

#if IPV6_NUIPADDR
    // Store as IPv4-mapped IPv6 address
    memset(addr, 0, sizeof(*addr));
    addr->s6_addr[10] = 0xff;
    addr->s6_addr[11] = 0xff;
    memcpy(&addr->s6_addr[12], &p->s_addr, sizeof(p->s_addr));
#else
    addr->s_addr = p->s_addr;
#endif
    return USP_ERR_OK;
}


/*********************************************************************//**
**
**  nu_ipaddr_from_in6addr
**
**  Converts an (IPv6) in6_addr structure to a nu_ipaddr_t structure
**
** \param   p - pointer to in6_addr structure to convert to a nu_ipaddr_t
** \param   addr - pointer to structure in which to return the nu_ipaddr_t
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
nu_ipaddr_from_in6addr(const struct in6_addr *p, nu_ipaddr_t *addr)
{
    if (p == NULL || addr == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

#if IPV6_NUIPADDR
    memcpy(addr, p, sizeof(*addr));
#else
    if (p->s6_addr[10] == 0xff && p->s6_addr[11] == 0xff &&
        p->s6_addr[8] == 0 && p->s6_addr[9] == 0 &&
        p->s6_addr[0] == 0 && p->s6_addr[1] == 0 &&
        p->s6_addr[2] == 0 && p->s6_addr[3] == 0 &&
        p->s6_addr[4] == 0 && p->s6_addr[5] == 0 &&
        p->s6_addr[6] == 0 && p->s6_addr[7] == 0) {
        memcpy(&addr->s_addr, &p->s6_addr[12], sizeof(addr->s_addr));
        return USP_ERR_OK;
    }
    USP_ERR_SetMessage("%s: Not an IPv4-mapped or compatible IPv6 address", __FUNCTION__);
#endif
    return USP_ERR_INTERNAL_ERROR;
}

/*********************************************************************//**
**
**  nu_ipaddr_equal
**
**  Determines whether two nu_ipaddr_t structures are equal
**
** \param   a1 - pointer to first nu_ipaddr_t structure
** \param   a1 - pointer to second nu_ipaddr_t structure
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
nu_ipaddr_equal(const nu_ipaddr_t *a1, const nu_ipaddr_t *a2, 
    bool *equalp)
{
    if (a1 == NULL || a2 == NULL || equalp == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

#if IPV6_NUIPADDR
    *equalp = (memcmp(a1->s6_addr, a2->s6_addr, sizeof(a1->s6_addr)) == 0);
#else
    *equalp = (a1->s_addr == a2->s_addr);
#endif
    return USP_ERR_OK;
}

/*********************************************************************//**
**
**  nu_ipaddr_copy
**
**  Copies from a src nu_ipaddr_t structure to a dest
**
** \param   dst - pointer to destination nu_ipaddr_t structure
** \param   src - pointer to source nu_ipaddr_t structure
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
nu_ipaddr_copy(nu_ipaddr_t *dest, const nu_ipaddr_t *src)
{
    if (dest == NULL || src == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    memcpy(dest, src, sizeof(nu_ipaddr_t));
    return USP_ERR_OK;
}

/*********************************************************************//**
**
**  nu_ipaddr_set_zero
**
**  Sets the specified nu_ipaddr_t to be the 'zero' IP address
**
** \param   addr - pointer to structure to set to the 'zero' IP address
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
nu_ipaddr_set_zero(nu_ipaddr_t *addr)
{
    if (addr == NULL) {
        USP_ERR_SetMessage("%s: Invalid argument", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

#if IPV6_NUIPADDR
    memset(addr, 0, sizeof(*addr));
#else
    addr->s_addr = 0;
#endif
    return USP_ERR_OK;
}


/*********************************************************************//**
**
**  nu_ipaddr_is_zero
**
**  Returns whether the specified nu_ipaddr_t is the 'zero' IP address
**  The 'zero' IP address is used as a magic number by clients to denote an invalid/uninitialised IP Address
**
** \param   addr - pointer to nu_ipaddr_t
**
** \return  true if the specified nu_ipaddr_t is the 'zero' IP address, false otherwise
**
**************************************************************************/
bool
nu_ipaddr_is_zero(const nu_ipaddr_t *addr)
{
    if (addr == NULL) {
        return true;
    }

#if IPV6_NUIPADDR
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        return (addr->s6_addr[12] == 0 && addr->s6_addr[13] == 0 &&
            addr->s6_addr[14] == 0 && addr->s6_addr[15] == 0);
    }
    return (memcmp(addr->s6_addr, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0);
#else
    return (addr->s_addr == 0);
#endif
}

/*********************************************************************//**
**
**  nu_ipaddr_get_interface_addr_from_dest_addr
**
**  Determines the ip address of the interface on which a packet will be sent,
**  based on the destination address of the packet
**
** \param   dest - destination address of the packet
** \param   if_addr - pointer to structure in which to return the interface address
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int nu_ipaddr_get_interface_addr_from_dest_addr(nu_ipaddr_t *dest, nu_ipaddr_t *if_addr)
{
    if (dest == NULL || if_addr == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    sa_family_t family;
    int err = nu_ipaddr_get_family(dest, &family);
    if (err != USP_ERR_OK) {
        return err;
    }

    struct sockaddr_storage sa;
    socklen_t sa_len;
    err = nu_ipaddr_to_sockaddr(dest, 1025, &sa, &sa_len);
    if (err != USP_ERR_OK) {
        return err;
    }

    int sock_fd = socket(family, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        USP_ERR_ERRNO("socket", errno);
        return USP_ERR_INTERNAL_ERROR;
    }

    err = connect(sock_fd, (struct sockaddr *)&sa, sa_len);
    if (err != 0) {
        USP_ERR_ERRNO("connect", errno);
        close(sock_fd);
        return USP_ERR_INTERNAL_ERROR;
    }

    sa_len = sizeof(sa);
    err = getsockname(sock_fd, (struct sockaddr *)&sa, &sa_len);
    if (err != 0) {
        USP_ERR_ERRNO("getsockname", errno);
        close(sock_fd);
        return USP_ERR_INTERNAL_ERROR;
    }

    err = nu_ipaddr_from_sockaddr_storage(&sa, if_addr, NULL);
    close(sock_fd);
    return err;
}

/*********************************************************************//**
**
**  nu_ipaddr_get_interface_addr_from_sock_fd
**
**  Determines the ip address of the interface on which a packet will be sent,
**  based on a socket that has connected to a destination address
**
** \param   sock_fd - socket
** \param   buf - pointer to buffer in which to return the string
** \param   bufsiz - size of buffer in which to return the string. This must be at least NU_IPADDRSTRLEN bytes long.
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int nu_ipaddr_get_interface_addr_from_sock_fd(int sock_fd, char *buf, int bufsiz)
{
    if (buf == NULL || bufsiz < NU_IPADDRSTRLEN) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    struct sockaddr_storage sa;
    socklen_t sa_len = sizeof(sa);
    int err = getsockname(sock_fd, (struct sockaddr *)&sa, &sa_len);
    if (err != 0) {
        USP_ERR_ERRNO("getsockname", errno);
        return USP_ERR_INTERNAL_ERROR;
    }

    nu_ipaddr_t if_addr;
    err = nu_ipaddr_from_sockaddr_storage(&sa, &if_addr, NULL);
    if (err != USP_ERR_OK) {
        return err;
    }

    return nu_ipaddr_to_str(&if_addr, buf, bufsiz);
}

/*********************************************************************//**
**
**  nu_ipaddr_get_interface_name_from_src_addr
**
**  Determines the name of an interface given it's source IP address
**
** \param   src_addr - source address of a network interface on the device
** \param   name - pointer to buffer in which to return the name of the interface that has the specified source address
** \param   name_len - size of buffer in which to return the name of the interface that has the specified source address
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int nu_ipaddr_get_interface_name_from_src_addr(char *src_addr, char *name, int name_len)
{
    if (src_addr == NULL || name == NULL || name_len <= 0) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    name[0] = '\0';
    struct ifaddrs *ifaddr_list = NULL;
    if (getifaddrs(&ifaddr_list) != 0) {
        USP_ERR_SetMessage("%s: getifaddrs failed: %s", __FUNCTION__, strerror(errno));
        return USP_ERR_INTERNAL_ERROR;
    }

    for (struct ifaddrs *ifa = ifaddr_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        sa_family_t family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) {
            continue;
        }

        void *in_addr;
        if (family == AF_INET) {
            in_addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        } else {
            in_addr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            if (NOT_GLOBAL_UNICAST((struct in6_addr *)in_addr)) {
                continue;
            }
        }

        char buf[NU_IPADDRSTRLEN];
        if (inet_ntop(family, in_addr, buf, sizeof(buf)) == NULL) {
            continue;
        }

        if (strcmp(buf, src_addr) == 0) {
            USP_STRNCPY(name, ifa->ifa_name, name_len);
            freeifaddrs(ifaddr_list);
            return USP_ERR_OK;
        }
    }

    freeifaddrs(ifaddr_list);
    USP_ERR_SetMessage("%s: No interface found for IP address %s", __FUNCTION__, src_addr);
    return USP_ERR_INTERNAL_ERROR;
}

/*********************************************************************//**
**
** nu_ipaddr_has_interface_addr_changed
**
** Determines whether the IP address of the specified interface has changed from the expected address
** This function is used to determine whether to restart a STOMP or CoAP connection
**
** \param   dev - name of interface to get IP Address of
** \param   expected_addr - expected IP address of interface
** \param   has_addr - pointer to variable in which to return whether the network interface has any IP address
**
** \return  true if the IP address of the interface has changed, false otherwise
**
**************************************************************************/
int nu_ipaddr_has_interface_addr_changed(char *dev, char *expected_addr, bool *has_addr)
{
    if (dev == NULL || expected_addr == NULL || has_addr == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return true;
    }

    *has_addr = false;
    struct ifaddrs *ifaddr_list = NULL;
    if (getifaddrs(&ifaddr_list) != 0) {
        USP_ERR_SetMessage("%s: getifaddrs failed: %s", __FUNCTION__, strerror(errno));
        return true;
    }

    for (struct ifaddrs *ifa = ifaddr_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, dev) != 0 || ifa->ifa_addr == NULL) {
            continue;
        }

        sa_family_t family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) {
            continue;
        }

        void *in_addr;
        if (family == AF_INET) {
            in_addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        } else {
            in_addr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            if (NOT_GLOBAL_UNICAST((struct in6_addr *)in_addr)) {
                continue;
            }
        }

        char buf[NU_IPADDRSTRLEN];
        if (inet_ntop(family, in_addr, buf, sizeof(buf)) == NULL) {
            continue;
        }

        *has_addr = true;
        if (strcmp(buf, expected_addr) == 0) {
            freeifaddrs(ifaddr_list);
            return false;
        }
    }

    freeifaddrs(ifaddr_list);
    return true;
}

/*********************************************************************//**
**
**  nu_ipaddr_get_ip_supported_families
**
**  Determines whether the device has any IPv4 address and any globally routable IPv6 address (on any of its interfaces)
**
** \param   ipv4_supported - pointer to variable in which to store whether IPv4 is supported
** \param   ipv6_supported - pointer to variable in which to store whether IPv6 is supported
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int nu_ipaddr_get_ip_supported_families(bool *ipv4_supported, bool *ipv6_supported)
{
    if (ipv4_supported == NULL || ipv6_supported == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    *ipv4_supported = false;
    *ipv6_supported = false;

    struct ifaddrs *ifaddr_list = NULL;
    if (getifaddrs(&ifaddr_list) != 0) {
        USP_ERR_ERRNO("getifaddrs", errno);
        return USP_ERR_INTERNAL_ERROR;
    }

    for (struct ifaddrs *ifa = ifaddr_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        sa_family_t family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            *ipv4_supported = true;
        } else if (family == AF_INET6) {
            struct in6_addr *addr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            if (!NOT_GLOBAL_UNICAST(addr)) {
                *ipv6_supported = true;
            }
        }
    }

    freeifaddrs(ifaddr_list);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** nu_ipaddr_is_valid_interface
**
** Determines whether the given interface name is present on the device
**
** \param   dev - name of interface to check
**
** \return  true if the interface exists, false, otherwise
**
**************************************************************************/
bool nu_ipaddr_is_valid_interface(const char *dev)
{
    if (dev == NULL) {
        return false;
    }

    struct ifaddrs *ifaddr_list = NULL;
    if (getifaddrs(&ifaddr_list) != 0) {
        return false;
    }

    bool is_found = false;
    for (struct ifaddrs *ifa = ifaddr_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, dev) == 0) {
            is_found = true;
            break;
        }
    }

    freeifaddrs(ifaddr_list);
    return is_found;
}

/*********************************************************************//**
**
**  tw_ulib_diags_family_to_protocol_version
**
**  Returns the string representing the protocol version to use for DNS lookups of hostname
**  ProtocolVersion selects which DNS record is used when performing the Host lookup for the diagnostic
**
** \param   address_family - address family to convert to a protocol version string
**
** \return  String form of specified IP address family
**
**************************************************************************/
char *tw_ulib_diags_family_to_protocol_version(int address_family)
{
    switch (address_family) {
        case AF_INET: return "IPv4";
        case AF_INET6: return "IPv6";
        case AF_UNSPEC: return "Any";
        default: return "Unknown";
    }
}

/*********************************************************************//**
**
**  tw_ulib_diags_lookup_host
**
**  Looks up the specified hostname, converting it into a nu_ipaddr_t IP address structure
**  Note the chosen IP address is determined by the following order :-
**          1) Which globally routable IP addresses the device has
**          2) The address family that the ACS requires (acs_family_pref)
**          3) The local interface IP address that the ACS requires (this may be more specific than the ACS address family
               in the case of address family=ANY, but CPE only has IPv4 or IPv6 address on the ACS specified interface)
**          3) Our dual stack preference
**
** \param   host - pointer to string containing hostname to lookup
** \param   acs_family_pref - The address family that the ACS requires for the Hostname resolution (AF_UNSPEC = don't care)
** \param   prefer_ipv6 - Set to true if we prefer an IPv6 address (and CPE is dual stack, so we have a choice)
** \param   acs_ipaddr_to_bind_to - IP address that the ACS has specified that should be used to contact the remote host (don't care = NULL or the zero address)
** \param   dst - pointer to structure in which to return the IP address of the remote host
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int
tw_ulib_diags_lookup_host(const char *host, int acs_family_pref, bool prefer_ipv6, nu_ipaddr_t *acs_ipaddr_to_bind_to, nu_ipaddr_t *dst)
{
    if (host == NULL || dst == NULL) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    int preferred_family = prefer_ipv6 ? AF_INET6 : AF_INET;
    if (acs_ipaddr_to_bind_to != NULL && !nu_ipaddr_is_zero(acs_ipaddr_to_bind_to)) {
        int err = nu_ipaddr_get_family(acs_ipaddr_to_bind_to, (sa_family_t *)&acs_family_pref);
        if (err != USP_ERR_OK) {
            return err;
        }
    }

    bool ipv4_supported, ipv6_supported;
    int err = nu_ipaddr_get_ip_supported_families(&ipv4_supported, &ipv6_supported);
    if (err != USP_ERR_OK) {
        return err;
    }

    struct addrinfo hints = {0};
    hints.ai_family = acs_family_pref;
    hints.ai_flags = AI_ADDRCONFIG;

    struct addrinfo *addr_list = NULL;
    err = getaddrinfo(host, NULL, &hints, &addr_list);
    if (err != 0) {
        USP_ERR_SetMessage("%s(host=%s, acs_family_pref=%s): getaddrinfo failed: %s",
            __FUNCTION__, host, tw_ulib_diags_family_to_protocol_version(acs_family_pref), gai_strerror(err));
        return USP_ERR_INTERNAL_ERROR;
    }

    bool found_result = false;
    sa_family_t selected_family = AF_INET;
    for (struct addrinfo *ai = addr_list; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET && ipv4_supported) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
            err = nu_ipaddr_from_inaddr(&sin->sin_addr, dst);
            if (err == USP_ERR_OK) {
                selected_family = AF_INET;
                found_result = true;
            } else {
                USP_ERR_SetMessage("%s(%s): nu_ipaddr_from_inaddr failed", __FUNCTION__, host);
            }
        } else if (ai->ai_family == AF_INET6 && ipv6_supported) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
            err = nu_ipaddr_from_in6addr(&sin6->sin6_addr, dst);
            if (err == USP_ERR_OK) {
                selected_family = AF_INET6;
                found_result = true;
            } else {
                USP_ERR_SetMessage("%s(%s): nu_ipaddr_from_in6addr failed", __FUNCTION__, host);
            }
        }

        if (acs_family_pref != AF_UNSPEC && found_result) {
            break;
        }
        if (found_result && selected_family == preferred_family) {
            break;
        }
    }

    freeaddrinfo(addr_list);
    if (!found_result) {
        USP_ERR_SetMessage("%s(%s): Failed to resolve hostname", __FUNCTION__, host);
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

#ifdef CONNECT_ONLY_OVER_WAN_INTERFACE
/*********************************************************************//**
**
** tw_ulib_dev_get_live_wan_address
**
** Gets the current 'live' WAN address (ie not the one stored in the CM DB)
** NOTE: If no IP address is found, then this function will return an empty string and EAGAIN.
**
** \param   buf - pointer to buffer in which to return. This must be at least NU_IPADDRSTRLEN bytes long.
** \param   bufsiz - size of buffer in which to return ASCII form of the IP address
**
** \return  USP_ERR_OK if successful, USP_ERR_INTERNAL_ERROR if no IP address was found, or an error occurred
**
**************************************************************************/
int tw_ulib_dev_get_live_wan_address(char *buf, size_t bufsiz)
{
    if (buf == NULL || bufsiz < NU_IPADDRSTRLEN) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    const char *dev = nu_macaddr_wan_ifname();
    bool prefer_ipv6 = DEVICE_LOCAL_AGENT_GetDualStackPreference();
    return tw_ulib_get_dev_ipaddr(dev, buf, bufsiz, prefer_ipv6);
}
#endif

/*********************************************************************//**
**
** tw_ulib_get_dev_ipaddr
**
** Gets the current IP address on the specified interface.
** NOTE: If no IP address is found, then this function will return an empty string and USP_ERR_INTERNAL_ERROR.
**
** \param   dev - name of interface to get IP Address of
** \param   addr - buffer in which to return the IP address (which for IPv4 will be a string of the form X.X.X.X)
**                 NOTE: This must be at least NU_IPADDRSTRLEN bytes long.
** \param   asiz - size of buffer in which to return the IP address
** \param   prefer_ipv6 - Set to true if prefer an IPv6 address (and CPE is dual stack, so we have a choice)
**
** \return  USP_ERR_OK if successful, USP_ERR_INTERNAL_ERROR if no IP address was found, or an error occurred
**
**************************************************************************/
int tw_ulib_get_dev_ipaddr(const char *dev, char *addr, size_t asiz, bool prefer_ipv6)
{
    if (dev == NULL || addr == NULL || asiz < NU_IPADDRSTRLEN) {
        USP_ERR_SetMessage("%s: Invalid arguments", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    if (strcmp(dev, "any") == 0) {
        USP_STRNCPY(addr, prefer_ipv6 ? "[::]" : "0.0.0.0", asiz);
        return USP_ERR_OK;
    }

    addr[0] = '\0';
    sa_family_t preferred_family = prefer_ipv6 ? AF_INET6 : AF_INET;

    struct ifaddrs *ifaddr_list = NULL;
    if (getifaddrs(&ifaddr_list) != 0) {
        USP_ERR_SetMessage("%s: getifaddrs failed: %s", __FUNCTION__, strerror(errno));
        return USP_ERR_INTERNAL_ERROR;
    }

    bool found_result = false;
    for (struct ifaddrs *ifa = ifaddr_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, dev) != 0 || ifa->ifa_addr == NULL) {
            continue;
        }

        sa_family_t family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) {
            continue;
        }

        void *in_addr;
        if (family == AF_INET) {
            in_addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        } else {
            in_addr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            if (NOT_GLOBAL_UNICAST((struct in6_addr *)in_addr)) {
                continue;
            }
        }

        if (inet_ntop(family, in_addr, addr, asiz) == NULL) {
            continue;
        }

        found_result = true;
        if (family == preferred_family) {
            break;
        }
    }

    freeifaddrs(ifaddr_list);
    if (!found_result) {
        USP_ERR_SetMessage("%s: No IP address found for interface %s", __FUNCTION__, dev);
        addr[0] = '\0';
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}
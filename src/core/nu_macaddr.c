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
 * @file nu_macaddr.c
 *
 * Network MAC utility functions for retrieving the WAN interface name and MAC address.
 * Ensures compatibility with Linux and macOS using platform-specific ioctl calls.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#ifdef __linux__
#include <net/if_arp.h>
#endif
#ifdef __APPLE__
#include <net/if_dl.h>
#endif
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>

#include "common_defs.h"
#include "nu_macaddr.h"
#include "usp_api.h"
#include "text_utils.h"

//------------------------------------------------------------------------------
// String, set by '-i' command line option to specify the network interface to be used by USP communications
char *usp_interface = NULL;

/*********************************************************************//**
**
** nu_macaddr_wan_ifname
**
** Returns the name of the WAN interface.
** This should be the interface that's used to connect to
** remote network services such as CWMP and XMPP.
** For example this may be 'eth0'
**
** \param   None
**
** \return  pointer to string containing name of the WAN interface
**
**************************************************************************/
char *nu_macaddr_wan_ifname(void)
{
    char *e;

    // Check command-line option
    if (usp_interface != NULL && *usp_interface != '\0') {
        return usp_interface;
    }

    // Check environment variable for override (e.g., for Docker or embedded systems)
    e = getenv("USP_BOARD_IFNAME");
    if (e != NULL && *e != '\0') {
        return e;
    }

    // Fallback to default
    return DEFAULT_WAN_IFNAME;
}

/**
 * @brief Retrieves the MAC address of the WAN interface.
 *
 * Uses platform-specific ioctl calls (SIOCGIFHWADDR on Linux, SIOCGIFMAC on macOS)
 * to get the MAC address of the WAN interface. Ensures the interface name is valid
 * and the output buffer is properly sized.
 *
 * @param buf Pointer to a buffer to store the 6-byte MAC address (must be at least MAC_ADDR_LEN bytes).
 * @return USP_ERR_OK if successful, USP_ERR_INTERNAL_ERROR on failure.
 */
int nu_macaddr_wan_macaddr(uint8_t *buf)
{
    if (buf == NULL) {
        USP_ERR_SetMessage("%s: Invalid buffer pointer", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Initialize output buffer
    memset(buf, 0, MAC_ADDR_LEN);

    // Get WAN interface name
    const char *ifname = nu_macaddr_wan_ifname();
    if (ifname == NULL || *ifname == '\0') {
        USP_ERR_SetMessage("%s: No valid WAN interface name", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Ensure interface name fits within IFNAMSIZ
    if (strlen(ifname) >= IFNAMSIZ) {
        USP_ERR_SetMessage("%s: Interface name '%s' exceeds maximum length (%d)", __FUNCTION__, ifname, IFNAMSIZ - 1);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Set up ifreq structure
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    USP_STRNCPY(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    // Create a socket for ioctl
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        USP_ERR_SetMessage("%s: socket() failed (errno=%d: %s)", __FUNCTION__, errno, strerror(errno));
        return USP_ERR_INTERNAL_ERROR;
    }

    // Get MAC address using platform-specific ioctl
    int err;
#ifdef __linux__
    err = ioctl(sock, SIOCGIFHWADDR, &ifr);
    if (err == -1) {
        USP_ERR_SetMessage("%s: ioctl(SIOCGIFHWADDR) failed for interface %s (errno=%d: %s)",
                           __FUNCTION__, ifname, errno, strerror(errno));
        close(sock);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Verify address family
    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        USP_ERR_SetMessage("%s: Interface %s has invalid address family %d (expected ARPHRD_ETHER)",
                           __FUNCTION__, ifname, ifr.ifr_hwaddr.sa_family);
        close(sock);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Copy MAC address to output buffer
    memcpy(buf, ifr.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
#elif defined(__APPLE__)
    err = ioctl(sock, SIOCGIFMAC, &ifr);
    if (err == -1) {
        USP_ERR_SetMessage("%s: ioctl(SIOCGIFMAC) failed for interface %s (errno=%d: %s)",
                           __FUNCTION__, ifname, errno, strerror(errno));
        close(sock);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Verify address family
    if (ifr.ifr_addr.sa_family != AF_LINK) {
        USP_ERR_SetMessage("%s: Interface %s has invalid address family %d (expected AF_LINK)",
                           __FUNCTION__, ifname, ifr.ifr_addr.sa_family);
        close(sock);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Copy MAC address to output buffer
    memcpy(buf, ifr.ifr_addr.sa_data, MAC_ADDR_LEN);
#else
    #error "Unsupported platform: Neither __linux__ nor __APPLE__ defined"
#endif

    close(sock);
    return USP_ERR_OK;
}

/*
    Copyright (C) 2003  Thomas Ries <tries@gmx.net>

    This file is part of Siproxd.
    
    Siproxd is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    
    Siproxd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with Siproxd; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
*/
#include "config.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(HAVE_LINUX_IP_MASQ_H)
/* masq specific stuff */
#include <asm/types.h>          /* For __uXX types */
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/ip_fw.h>        /* For IP_FW_MASQ_CTL */
#include <linux/ip_masq.h>      /* For specific masq defs */
#include <asm/param.h>
#endif

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "rtpproxy.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";


#if defined(HAVE_LINUX_IP_MASQ_H)
/* socket for controlling the MASQ tunnels */
static int masq_ctl_sock=0;

int rtp_mchains_create(struct in_addr lcl_addr, int lcl_port,
                       struct in_addr msq_addr, int msq_port) {
   int uid,euid;
   int sts=STS_SUCCESS;
   struct ip_masq_ctl masq;

   /* elevate privileges */
   uid=getuid();
   euid=geteuid();
   if (uid != euid) seteuid(0);

   if (geteuid()!=0) {
      ERROR("create_listening_masq: must be running under UID root!");
      return STS_FAILURE;
   }

   if (masq_ctl_sock==0) {
      masq_ctl_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
      if (masq_ctl_sock<0) {
         ERROR("create_listening_masq: allocating control socket() failed: %s",
               strerror(errno));
         sts = STS_FAILURE;
         goto exit;
      }
   }

   memset (&masq, 0, sizeof (masq));

   masq.m_target       = IP_MASQ_TARGET_USER;
   masq.m_cmd          = IP_MASQ_CMD_INSERT;
   masq.u.user.protocol= IPPROTO_UDP;

   memcpy(&masq.u.user.saddr, &lcl_addr, sizeof(lcl_addr));
   masq.u.user.sport   = htons(lcl_port);

   memcpy(&masq.u.user.maddr, &msq_addr, sizeof(msq_addr));
   masq.u.user.mport   = htons(msq_port);

   if (setsockopt(masq_ctl_sock, IPPROTO_IP, 
                  IP_FW_MASQ_CTL, (char *)&masq, sizeof(masq)))    {
      DEBUGC(DBCLASS_RTP, "create_listening_masq: setsockopt() failed: %s",
            strerror(errno));
       sts = STS_FAILURE;
       goto exit;
   }


exit:
   /* drop privileges */
   if (uid != euid)  seteuid(euid);
   return sts;
}

#else
/*
 * don't have ipchains - dummy routines and complain
 */

int rtp_mchains_create(struct in_addr lcl_addr, int lcl_port,
                       struct in_addr msq_addr, int msq_port) {
   ERROR("IPCHAINS support is not enabled (compile time config option)");
   return STS_FAILURE;
}
#endif

int rtp_mchains_delete (struct in_addr lcl_addr, int lcl_port,
                        struct in_addr msq_addr, int msq_port) {
   /* nothing to do here, just let the tunnel time out */
   return STS_SUCCESS;
}

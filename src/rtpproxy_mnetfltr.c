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
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(HAVE_LINUX_NETFILTER_H)
/* iptables/netfilter specific stuff */
//&&&&
#endif

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "rtpproxy.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";


#if defined(HAVE_LINUX_NETFILTER_H)

static char *ipchains_exe="/sbin/iptables";
static char *add_rule =
    "%s -t nat -A PREROUTING -p udp --destination-port %i -j DNAT "
    "--to-destination %s:%i";
static char *del_rule =
    "%s -t nat -D PREROUTING -p udp --destination-port %i -j DNAT "
    "--to-destination %s:%i";

/*
 * lcl_addr	IP of local UA
 * lcl_port	port of local UA
 * msq_addr	masqueraded address (public IP of proxy)
 * msq_port	masqueraded port (where siproxd wants to receive RTP traffic)
 */
int rtp_mnetfltr_create (struct in_addr lcl_addr, int lcl_port,
                         struct in_addr msq_addr, int msq_port) {
   int uid,euid;
   int sts;
   char tmp[256];

   INFO("rtp_mchains_create");

   /* Still an Hack I don't like - use a system() call to alter the FW */
   sprintf(tmp, add_rule, ipchains_exe, msq_port, utils_inet_ntoa(lcl_addr),
                                        lcl_port);
   
   DEBUGC(DBCLASS_RTP,"rtp_mnetfltr_create: add FW rule:[%s]",tmp);

   /* elevate privileges */
   uid=getuid();
   euid=geteuid();
   if (uid != euid) seteuid(0);

   if (geteuid()!=0) {
      ERROR("create_listening_masq: must be running under UID root!");
      return STS_FAILURE;
   }

   sts = system(tmp);
   if (sts <0) {
      ERROR("rtp_mnetfltr_create: system() failed with sts=%i", sts);
   }

   /* drop privileges */
   if (uid != euid) seteuid(euid);
   return STS_SUCCESS;
}

int rtp_mnetfltr_delete (struct in_addr lcl_addr, int lcl_port,
                         struct in_addr msq_addr, int msq_port) {
   int uid,euid;
   int sts;
   char tmp[256];

   INFO("rtp_mchains_delete");

   /* Still an Hack I don't like - use a system() call to alter the FW */
   sprintf(tmp, del_rule, ipchains_exe, msq_port, utils_inet_ntoa(lcl_addr), 
                                        lcl_port);
   
   DEBUGC(DBCLASS_RTP,"rtp_mnetfltr_delete: del FW rule:[%s]",tmp);

   /* elevate privileges */
   uid=getuid();
   euid=geteuid();
   if (uid != euid) seteuid(0);

   if (geteuid()!=0) {
      ERROR("create_listening_masq: must be running under UID root!");
      return STS_FAILURE;
   }

   sts = system(tmp);
   if (sts <0) {
      ERROR("rtp_mnetfltr_create: system() failed with sts=%i", sts);
   }

   /* drop privileges */
   if (uid != euid) seteuid(euid);
   return STS_SUCCESS;
}
#else
/*
 * don't have iptables - dummy routines and complain
 */

int rtp_mnetfltr_create (struct in_addr lcl_addr, int lcl_port,
                         struct in_addr msq_addr, int msq_port) {
   ERROR("NETFILTER support is not enabled (compile time config option)");
   return STS_FAILURE;
}

int rtp_mnetfltr_delete (struct in_addr lcl_addr, int lcl_port,
                        struct in_addr msq_addr, int msq_port) {
   ERROR("NETFILTER support is not enabled (compile time config option)");
   return STS_FAILURE;
}
#endif

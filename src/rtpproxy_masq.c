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


/* configuration storage */
extern struct siproxd_config configuration;

/* table to remember all active rtp proxy streams */
extern rtp_proxytable_t rtp_proxytable[];

#if defined(HAVE_LINUX_IP_MASQ_H)
/* socket for controlling the MASQ tunnels */
static int masq_ctl_sock=0;

/*
 * table to remember all active rtp proxy streams
 */
rtp_proxytable_t rtp_proxytable[RTPPROXY_SIZE];

/* table to remember all masquerading tunnels (1:1 with rtp_proxytable) */
struct ip_masq_ctl masq_table[RTPPROXY_SIZE];

/*
 * local prototypes
 */
static int _create_listening_masq(struct ip_masq_ctl *masq,
                           struct in_addr lcl_addr, int lcl_port,
                           struct in_addr msq_addr, int msq_port);

/************************************************************
  THIS HERE WILL ONLY WORK IF SIPROXD IS STARTED SUID ROOT !!
  However it is working when started root and then changed
  UID to eg. nobody - we'll just raise the privileged when
  we need to fiddle with the masquerading
*************************************************************/

/*
 * initialize rtp_masq
 *
 * RETURNS
 *	STS_SUCCESS on success
 */
int rtp_masq_init( void ) {

   /* clean proxy table */
   memset (rtp_proxytable, 0, sizeof(rtp_proxytable));

   return STS_SUCCESS;
}



int rtp_masq_start_fwd(osip_call_id_t *callid, int media_stream_no,
                       struct in_addr outbound_ipaddr, int *outbound_lcl_port,
                       struct in_addr lcl_client_ipaddr, int lcl_clientport) {
   int sts, i;
   int freeidx;
   time_t t;
   
   if (callid == NULL) {
      ERROR("rtp_relay_start_fwd: callid is NULL!");
      return STS_FAILURE;
   }


   /*
    * life insurance: check size of received call_id strings
    * I don't know what the maximum allowed size within SIP is,
    * so if this test fails maybe it's just necessary to increase
    * the constants CALLIDNUM_SIZE and/or CALLIDHOST_SIZE.
    */
   if (strlen(callid->number) > CALLIDNUM_SIZE) {
      ERROR("rtp_relay_start_fwd: received callid number "
            "has too many characters (%i, max=%i)",
            strlen(callid->number),CALLIDNUM_SIZE);
      return STS_FAILURE;
   }
   if (strlen(callid->host) > CALLIDHOST_SIZE) {
      ERROR("rtp_relay_start_fwd: received callid host "
            "has too many characters (%i, max=%i)",
            strlen(callid->host),CALLIDHOST_SIZE);
      return STS_FAILURE;
   }

   /*
    * Age proxy table:
    * Just throw out expired (timed out) records. The proxy table
    * here for the MASQ module is only used to eliminate "doubles"
    * during INVITE/ACK. Later on, managing (aging & cleaning) the
    * masquerading tunnels is done by the kernel (IPMASQ).
    */
   time(&t);
   for (i=0; i<RTPPROXY_SIZE; i++) {
      if ( (rtp_proxytable[i].sock != 0) &&
	   ((rtp_proxytable[i].timestamp+configuration.rtp_timeout)<t)) {
         /* this one has expired, clean it up */
         DEBUGC(DBCLASS_RTP,"cleaning proxy slot #%i %s@%s", i,
                rtp_proxytable[i].callid_number,
                rtp_proxytable[i].callid_host);
         memset(&rtp_proxytable[i], 0, sizeof(rtp_proxytable[0]));
      }
   }



   DEBUGC(DBCLASS_RTP,"rtp_masq_start_fwd: starting RTP proxy "
          "stream for: %s@%s #=%i",
          callid->number, callid->host, media_stream_no);

   /*
    * figure out, if this is an request to start an RTP proxy stream
    * that is already existing (identified by SIP Call-ID and
    * media_stream_no). This can be due to UDP repetitions of the
    * INVITE request...
    */
   for (i=0; i<RTPPROXY_SIZE; i++) {
      if((strcmp(rtp_proxytable[i].callid_number, callid->number)==0) &&
	 (strcmp(rtp_proxytable[i].callid_host, callid->host)==0) &&
         (rtp_proxytable[i].media_stream_no == media_stream_no) ) {
         /* return the already known port number */
         DEBUGC(DBCLASS_RTP,"RTP stream already active (port=%i, "
                "id=%s, #=%i)", rtp_proxytable[i].outboundport,
                rtp_proxytable[i].callid_number,
                rtp_proxytable[i].media_stream_no);
         return STS_SUCCESS;
      }
   }


   /*
    * find first free slot in rtp_proxytable
    */
   freeidx=-1;
   for (i=0; i<RTPPROXY_SIZE; i++) {
      if (rtp_proxytable[i].sock==0) {
         freeidx=i;
	 break;
      }
   }

   /* rtp_proxytable port pool full? */
   if (freeidx == -1) {
      ERROR("rtp_masq_start_fwd: rtp_proxytable is full!");
      return  STS_FAILURE;
   }

/*
 * do loop over the range of available ports (7070-...) until able to 
 * allocate a UDP tunnel. If not successful - Buh! return port=0
 */
   for (i=configuration.rtp_port_low; i<=configuration.rtp_port_high; i++) {
      *outbound_lcl_port=i;
      sts = _create_listening_masq(&masq_table[freeidx],
                             lcl_client_ipaddr, lcl_clientport,
                             outbound_ipaddr, *outbound_lcl_port);
      /* if success break, else try further on */
      if (sts == STS_SUCCESS) break;
      *outbound_lcl_port=0;
   } /* for i */

   if (*outbound_lcl_port) {
      /* write entry into rtp_proxytable slot (freeidx) */
      DEBUGC(DBCLASS_RTP,"rtp_masq_start_fwd: using proxy slot %i",freeidx);
      rtp_proxytable[freeidx].sock=1;
      strcpy(rtp_proxytable[freeidx].callid_number, callid->number);
      strcpy(rtp_proxytable[freeidx].callid_host, callid->host);
      rtp_proxytable[freeidx].media_stream_no = media_stream_no;
      memcpy(&rtp_proxytable[freeidx].outbound_ipaddr,
             &outbound_ipaddr, sizeof(struct in_addr));
      rtp_proxytable[freeidx].outboundport=*outbound_lcl_port;
      memcpy(&rtp_proxytable[freeidx].inbound_client_ipaddr,
             &lcl_client_ipaddr, sizeof(struct in_addr));
      rtp_proxytable[freeidx].inbound_client_port=lcl_clientport;
      time(&rtp_proxytable[freeidx].timestamp);
   }

   DEBUGC(DBCLASS_RTP,"rtp_masq_start_fwd: masq address & port:%s:%i",
          inet_ntoa(outbound_ipaddr),outbound_lcl_port);
   return (*outbound_lcl_port)?STS_SUCCESS:STS_FAILURE;
}


int rtp_masq_stop_fwd(osip_call_id_t *callid) {
   int i;
   int got_match=0;
   
   /* let the UDP tunnel time-out */

   if (callid == NULL) {
      ERROR("rtp_relay_stop_fwd: callid is NULL!");
      return STS_FAILURE;
   }

   for (i=0; i<RTPPROXY_SIZE; i++) {
      if ((callid->number==NULL) || (callid->host==NULL)) break;
      if( rtp_proxytable[i].sock &&
         (strcmp(rtp_proxytable[i].callid_number, callid->number)==0) &&
	 (strcmp(rtp_proxytable[i].callid_host, callid->host)==0) ) {
         DEBUGC(DBCLASS_RTP,"rtp_masq_stop_fwd: cleaning proxy slot %i",i);
         memset(&rtp_proxytable[i], 0, sizeof(rtp_proxytable[0]));
         got_match=1;
         }
 
   }

   /* did not find an active stream... */
   if (!got_match) {
      DEBUGC(DBCLASS_RTP,"rtp_masq_stop_fwd: can't find active stream for %s@%s",
             callid->number, callid->host);
      return STS_FAILURE;
   }

   return STS_SUCCESS;
}


/*
 * helper routines
 */
static int _create_listening_masq(struct ip_masq_ctl *masq,
                           struct in_addr lcl_addr, int lcl_port,
                           struct in_addr msq_addr, int msq_port) {
   int uid,euid;
   int sts=STS_SUCCESS;

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

   memset (masq, 0, sizeof (*masq));

   masq->m_target       = IP_MASQ_TARGET_USER;
   masq->m_cmd          = IP_MASQ_CMD_INSERT;
   masq->u.user.protocol= IPPROTO_UDP;

   memcpy(&masq->u.user.saddr, &lcl_addr, sizeof(lcl_addr));
   masq->u.user.sport   = htons(lcl_port);

   memcpy(&masq->u.user.maddr, &msq_addr, sizeof(msq_addr));
   masq->u.user.mport   = htons(msq_port);

   if (setsockopt(masq_ctl_sock, IPPROTO_IP, 
                  IP_FW_MASQ_CTL, (char *)masq, sizeof(*masq)))    {
      ERROR("create_listening_masq: setsockopt() failed: %s",
            strerror(errno));
       sts = STS_FAILURE;
       goto exit;
   }

#if 0
  /*
   * set short timeout for expiration
   */
   masq->m_cmd          = IP_MASQ_CMD_SET;
   masq->u.user.timeout = 10*HZ;
   if (setsockopt(masq_ctl_sock, IPPROTO_IP, 
                  IP_FW_MASQ_CTL, (char *)masq, sizeof(*masq)))    {
      ERROR("create_listening_masq: setsockopt() failed: %s",
            strerror(errno));
       sts = STS_FAILURE;
       goto exit;
   }
#endif

exit:
   /* drop privileges */
   if (uid != euid)  seteuid(euid);
   return sts;
}

#else
/*
 * don't have ipchains or iptables - dummy routines and complain
 */

int rtp_masq_init( void ) {
   ERROR("Masquerading support is not enabled (compile time config option)");
   return STS_FAILURE;
}
int rtp_masq_start_fwd(osip_call_id_t *callid, int media_stream_no,
                       struct in_addr outbound_ipaddr, int *outbound_lcl_port,
                       struct in_addr lcl_client_ipaddr, int lcl_clientport) {
   outbound_lcl_port=0;
   return STS_FAILURE;
}
int rtp_masq_stop_fwd(osip_call_id_t *callid) {
   return STS_FAILURE;
}
#endif

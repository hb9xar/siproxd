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

#if defined(HAVE_LINUX_IP_MASQ_H) || defined(HAVE_LINUX_NETFILTER_H)

/*
 * table to remember all active rtp proxy streams
 */
rtp_proxytable_t rtp_proxytable[RTPPROXY_SIZE];


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

   if (configuration.rtp_proxy_enable == 2) { // MASQ tunnels (ipchains)
#if !defined(HAVE_LINUX_IP_MASQ_H)
      ERROR("IPCHAINS support not built in");
      return STS_FAILURE;
#endif
   } else if (configuration.rtp_proxy_enable == 3) { // MASQ tunnels (netfilter)
#if !defined(HAVE_LINUX_NETFILTER_H)
      ERROR("NETFILTER/IPTABLES support not built in");
      return STS_FAILURE;
#endif
   }
   return STS_SUCCESS;
}


int rtp_masq_start_fwd(osip_call_id_t *callid, int media_stream_no,
                       struct in_addr outbound_ipaddr, int *outbound_lcl_port,
                       struct in_addr lcl_client_ipaddr, int lcl_clientport) {
   int sts=STS_FAILURE;
   int i, j;
   int freeidx;
   time_t t;
   osip_call_id_t cid;
   
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
   if (callid->number && strlen(callid->number) > CALLIDNUM_SIZE) {
      ERROR("rtp_relay_start_fwd: received callid number "
            "has too many characters (%i, max=%i)",
            strlen(callid->number),CALLIDNUM_SIZE);
      return STS_FAILURE;
   }
   if (callid->host && strlen(callid->host) > CALLIDHOST_SIZE) {
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
    /*&&&&
      RACE CONDITIONS! A slot may be timed out, even if the actual
      masquerading tunnel is still active. A following new
      INVITE then tries to use the believed free port -> Buh
      - Can we poll (/proc/something) to figure out if the tunnel
        is still active before deleting? This would require knowledge
	of the text layout in /proc/xxx.
      - are there some other possibilities (netfilter/libiptc)?
      - introduce some kind of connection STATE to the proxy table.
        Timeout based discarding only is active for non-established.
	An INVITE would set the STATE to CONNECTING, the following
	ACK to CONNECTED. A CONNECTED entry can only be deleted by
	a BYE or CANCEL.
      - NETFILTER: during startup (RTP initialization) siproxd should
        clean left over entries that are within the RTP proxy port range
     */
   time(&t);
   for (i=0; i<RTPPROXY_SIZE; i++) {
      if ((rtp_proxytable[i].sock != 0) &&
	 ((rtp_proxytable[i].timestamp+configuration.rtp_timeout)<t)) {
         /* this one has expired, delete it */
         cid.number = rtp_proxytable[i].callid_number;
         cid.host   = rtp_proxytable[i].callid_host;
         rtp_masq_stop_fwd(&cid);
         DEBUGC(DBCLASS_RTP,"deleting expired proxy slot #%i %s@%s", i,
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
   freeidx=-1;
   for (i=0; i<RTPPROXY_SIZE; i++) {
      cid.number = rtp_proxytable[i].callid_number;
      cid.host   = rtp_proxytable[i].callid_host;
      if (rtp_proxytable[i].sock != 0) {
         if((compare_callid(callid, &cid) == STS_SUCCESS) &&
            (rtp_proxytable[i].media_stream_no == media_stream_no)) {
            /* return the already known port number */
            *outbound_lcl_port=rtp_proxytable[i].outboundport;
            DEBUGC(DBCLASS_RTP,"RTP stream already active (port=%i, "
                   "id=%s, #=%i)", rtp_proxytable[i].outboundport,
                   rtp_proxytable[i].callid_number,
                   rtp_proxytable[i].media_stream_no);
	    return STS_SUCCESS;
         } /* compare */
      } else {
         /* remember the first free slot */
         if (freeidx < 0) freeidx=i;
      } /* if .sock */
   } /* for i */

   /* rtp_proxytable port pool full? */
   if (freeidx == -1) {
      ERROR("rtp_masq_start_fwd: rtp_proxytable is full!");
      return  STS_FAILURE;
   }

/*
 * do loop over the range of available ports (7070-...) until able to 
 * allocate a UDP tunnel with an even port number.  If none can be found
 * available - Buh! return port=0
 */
   for (i=configuration.rtp_port_low; i<=configuration.rtp_port_high; i+=2) {
      /* check if this port is already allocated in another stream.
       * IPCHAINS will print errors in SYSLOG when I try to use
       * the same port twice (IF it is still 'open' - no DST address
       * known yet) */
      DEBUGC(DBCLASS_RTP,"rtp_masq_start_fwd: checking port %i",i);
      for (j=0; j<RTPPROXY_SIZE; j++) {
         if (rtp_proxytable[j].sock ==0) continue;
         if (rtp_proxytable[j].outboundport == i) {
            DEBUGC(DBCLASS_RTP,"rtp_masq_start_fwd: port %i occupied",i);
            break;
         }
      }
      if (j < RTPPROXY_SIZE) continue; /* try next port */

      DEBUGC(DBCLASS_RTP,"rtp_masq_start_fwd: using port %i",i);

      *outbound_lcl_port=i;

      /* add masquerading entry */
      if (configuration.rtp_proxy_enable == 2) { // ipchains
         sts = rtp_mchains_create(lcl_client_ipaddr, lcl_clientport,
                                  outbound_ipaddr, *outbound_lcl_port);
      } else if (configuration.rtp_proxy_enable == 3) { // netfilter/iptables
         sts = rtp_mnetfltr_create(lcl_client_ipaddr, lcl_clientport,
                                   outbound_ipaddr, *outbound_lcl_port);
      }
      /* if success break, else try further on */
      if (sts == STS_SUCCESS) break;
      *outbound_lcl_port=0;
   } /* for i */

   if (*outbound_lcl_port) {
      /* write entry into rtp_proxytable slot (freeidx) */
      DEBUGC(DBCLASS_RTP,"rtp_masq_start_fwd: using proxy slot %i",freeidx);
      rtp_proxytable[freeidx].sock=1;

      if (callid->number) {
         strcpy(rtp_proxytable[freeidx].callid_number, callid->number);
      } else {
         rtp_proxytable[freeidx].callid_number[0]='\0';
      }

      if (callid->host) {
         strcpy(rtp_proxytable[freeidx].callid_host, callid->host);
      } else {
         rtp_proxytable[freeidx].callid_host[0]='\0';
      }

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
          utils_inet_ntoa(outbound_ipaddr),*outbound_lcl_port);
   return (*outbound_lcl_port)?STS_SUCCESS:STS_FAILURE;
}


int rtp_masq_stop_fwd(osip_call_id_t *callid) {
   int sts=STS_FAILURE;
   int i;
   int got_match=0;
   osip_call_id_t cid;
   
   /* let the UDP tunnel time-out */

   if (callid == NULL) {
      ERROR("rtp_relay_stop_fwd: callid is NULL!");
      return STS_FAILURE;
   }

   for (i=0; i<RTPPROXY_SIZE; i++) {
      cid.number = rtp_proxytable[i].callid_number;
      cid.host   = rtp_proxytable[i].callid_host;

      if (rtp_proxytable[i].sock &&
         (compare_callid(callid, &cid) == STS_SUCCESS)) {

         /* remove masquerading entry */
         if (configuration.rtp_proxy_enable == 2) { // ipchains
            DEBUGC(DBCLASS_RTP,"rtp_masq_stop_fwd: stop RTP proxy slot %i "
	           "(IPCHAINS)",i);
            sts = rtp_mchains_delete(
	             rtp_proxytable[i].inbound_client_ipaddr,
		     rtp_proxytable[i].inbound_client_port,
		     rtp_proxytable[i].outbound_ipaddr,
		     rtp_proxytable[i].outboundport);
         } else if (configuration.rtp_proxy_enable == 3) { // netfilter/iptables
            DEBUGC(DBCLASS_RTP,"rtp_masq_stop_fwd: stop RTP proxy slot %i "
	           "(NETFILTER)",i);
            sts = rtp_mnetfltr_delete(
	             rtp_proxytable[i].inbound_client_ipaddr,
		     rtp_proxytable[i].inbound_client_port,
		     rtp_proxytable[i].outbound_ipaddr,
		     rtp_proxytable[i].outboundport);
         }

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

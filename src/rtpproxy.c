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

#include <netinet/in.h>

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "rtpproxy.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";


/* configuration storage */
extern struct siproxd_config configuration;

/*
 * initialize and create rtp_proxy
 *
 * RETURNS
 *	STS_SUCCESS on success
 */
int rtpproxy_init( void ) {
  int sts=STS_FAILURE;

   if (configuration.rtp_proxy_enable == 0) {
      sts = STS_SUCCESS;
   } else if (configuration.rtp_proxy_enable == 1) { // Relay
      sts = rtp_relay_init ();
   } else if (configuration.rtp_proxy_enable == 2) { // MASQ tunnels (ipchains)
      sts = rtp_masq_init ();
   } else if (configuration.rtp_proxy_enable == 3) { // MASQ tunnels (netfilter)
      sts = rtp_masq_init ();
   } else {
      ERROR("CONFIG: rtp_proxy_enable has invalid value",
            configuration.rtp_proxy_enable);
   }

   return sts;
}

/*
 * start an rtp stream on the proxy
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int rtp_start_fwd (osip_call_id_t *callid, int media_stream_no,
		   struct in_addr outbound_ipaddr, int *outboundport,
                   struct in_addr lcl_client_ipaddr, int lcl_clientport) {
  int sts=STS_FAILURE;

   if (configuration.rtp_proxy_enable == 0) {
      sts = STS_SUCCESS;
   } else if (configuration.rtp_proxy_enable == 1) { // Relay
      sts = rtp_relay_start_fwd (callid, media_stream_no,
                                  outbound_ipaddr, outboundport,
                                  lcl_client_ipaddr, lcl_clientport);
   } else if (configuration.rtp_proxy_enable == 2) { // MASQ tunnels (ipchains)
      sts = rtp_masq_start_fwd (callid, media_stream_no,
                                 outbound_ipaddr, outboundport,
                                 lcl_client_ipaddr, lcl_clientport);
   } else if (configuration.rtp_proxy_enable == 3) { // MASQ tunnels (netfilter)
      sts = rtp_masq_start_fwd (callid, media_stream_no,
                                   outbound_ipaddr, outboundport,
                                   lcl_client_ipaddr, lcl_clientport);
   } else {
      ERROR("CONFIG: rtp_proxy_enable has invalid value",
            configuration.rtp_proxy_enable);
   }

   return sts;
}


/*
 * stop a rtp stream on the proxy
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int rtp_stop_fwd (osip_call_id_t *callid) {
   int sts = STS_FAILURE;

   if (configuration.rtp_proxy_enable == 0) {
      sts = STS_SUCCESS;
   } else if (configuration.rtp_proxy_enable == 1) { // Relay
      sts = rtp_relay_stop_fwd(callid, 0);
   } else if (configuration.rtp_proxy_enable == 2) { // MASQ tunnels (ipchains)
      sts = rtp_masq_stop_fwd(callid);
   } else if (configuration.rtp_proxy_enable == 3) { // MASQ tunnels (netfilter)
      sts = rtp_masq_stop_fwd(callid);
   } else {
      ERROR("CONFIG: rtp_proxy_enable has invalid value",
            configuration.rtp_proxy_enable);
   }

   return sts;
}

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

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "rtpproxy.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";


/* configuration storage */
extern struct siproxd_config configuration;

/*
 * table to remember all active rtp proxy streams
 */
extern rtp_proxytable_t rtp_proxytable[];



void rtp_relay (int num_fd, fd_set *fdset, time_t t) {
   int i;
   int count;
   int sts;
   static int rtp_socket=0;
   static char rtp_buff[RTP_BUFFER_SIZE];
   /* check for data available and send to destination */
   for (i=0;(i<RTPPROXY_SIZE) && (num_fd>0);i++) {
      if ( (rtp_proxytable[i].sock != 0) && 
	    FD_ISSET(rtp_proxytable[i].sock, fdset) ) {
         /* yup, have some data to send */

	 /* read from sock rtp_proxytable[i].sock*/
         count=read(rtp_proxytable[i].sock, rtp_buff, RTP_BUFFER_SIZE);

#ifdef MOREDEBUG /*&&&&*/
if (count<0) {WARN("read() returned error [%s]",strerror(errno));}
#endif

	 /* write to dest via socket rtp_inbound*/
         sts=sipsock_send_udp(&rtp_socket,
	                  rtp_proxytable[i].inbound_client_ipaddr,
			  rtp_proxytable[i].inbound_client_port,
			  rtp_buff, count, 0); /* don't dump it */
#ifdef MOREDEBUG /*&&&&*/
if (sts != STS_SUCCESS) {WARN("sipsock_send_udp() returned error");}
#endif
         /* update timestamp of last usage */
         rtp_proxytable[i].timestamp=t;

	 num_fd--;
      }
   } /* for i */

}



int rtp_relay_start_fwd(int *sock, int *port, struct in_addr outbound_ipaddr) {
   int i, j;
   /* TODO: randomize the port allocation - start at a random offset to
         search in the allowed port range (so some modulo stuff w/
	 random start offset 
	 - for i=x to (p1-p0)+x; p=p0+mod(x,p1-p0) */

   /* find a local outbound port number to use and bind to it*/
   *sock=0;
   *port=0;
   for (i=configuration.rtp_port_low; i<=configuration.rtp_port_high; i++) {
      for (j=0; j<RTPPROXY_SIZE; j++) {
         /* outbound port already in use */
         if ((memcmp(&rtp_proxytable[j].outbound_ipaddr,
	             &outbound_ipaddr, sizeof(struct in_addr))== 0) &&
	     (rtp_proxytable[j].outboundport == i) ) break;
      }

      /* port is available, try to allocate */
      if (j == RTPPROXY_SIZE) {
         *port=i;
         *sock=sockbind(outbound_ipaddr, *port, 0);
         /* if success break, else try further on */
         if (*sock) break;
      }
   } /* for i */

   return (*sock)?STS_SUCCESS:STS_FAILURE;
}


int rtp_relay_stop_fwd(int sock) {
   int sts;

   sts = close(sock);
   return sts;
}

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

#define CALLIDNUM_SIZE	256
#define CALLIDHOST_SIZE	32

typedef struct {
   int sock;
   char callid_number[CALLIDNUM_SIZE];          /* call ID */
   char callid_host[CALLIDHOST_SIZE];           /*  --"--  */
   int media_stream_no;
   struct in_addr outbound_ipaddr;              /* lcl outbound IP */
   int outboundport;                            /* lcl allocd outbound port */
   struct in_addr inbound_client_ipaddr;        /* lcl inbound UA IP */
   int inbound_client_port;                     /* lcl inbound UA port */
   time_t timestamp;                            /* last 'stream alive' TS */
} rtp_proxytable_t;

/*
 * RTP relay
 */
int  rtp_relay_init(void);
int  rtp_relay_start_fwd (osip_call_id_t *callid, int media_stream_no,
		          struct in_addr outbound_ipaddr, int *outboundport,
                          struct in_addr lcl_client_ipaddr, int lcl_clientport);
int  rtp_relay_stop_fwd (osip_call_id_t *callid, int nolock);


/*
 * RTP masquerading
 */
int  rtp_masq_init(void);
int  rtp_masq_start_fwd (osip_call_id_t *callid, int media_stream_no,
		          struct in_addr outbound_ipaddr, int *outboundport,
                          struct in_addr lcl_client_ipaddr, int lcl_clientport);
int  rtp_masq_stop_fwd (osip_call_id_t *callid);

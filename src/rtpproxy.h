/*
    Copyright (C) 2003-2009  Thomas Ries <tries@gmx.net>

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

/* $Id$ */

#if defined(HAVE_SYS_TIME_H)
# include <sys/time.h>
#endif

#define CALLIDNUM_SIZE	256
#define CALLIDHOST_SIZE	128

/* Buffer structure to store an RTP frame */
typedef char rtp_buff_t[RTP_BUFFER_SIZE];

/* Time control structure to be used with De-jitter feature */
typedef struct {
   struct timeval starttime ;
   int    calccount ;
   int    dejitter ;
   struct timeval dejitter_tv ;
   double dejitter_d ;
   int    time_code_a ;
   double received_a ;				/* time in �sec since epoch */
   int    time_code_b ;
   double received_b ;				/* time in �sec since epoch */
   int    time_code_c ;
   double received_c ;				/* time in �sec since epoch */
} timecontrol_t ;

typedef struct {
   int  rtp_rx_sock;				/* rx socket (0 -> free slot)*/
   int  rtp_tx_sock;				/* tx socket */
   int  rtp_con_rx_sock;			/* rx socket rtcp */
   int  rtp_con_tx_sock;			/* tx socket rtcp */
   char callid_number[CALLIDNUM_SIZE];		/* call ID */
   char callid_host[CALLIDHOST_SIZE];		/*  --"--  */
   client_id_t client_id;
   int  cseq;
   int  direction;				/* Direction of RTP stream */
   int  call_direction;				/* Direction of Call DIR_x */
   int  media_stream_no;
   timecontrol_t tc;				/* de-jitter feature */
   struct in_addr local_ipaddr;			/* local IP */
   int  local_port;				/* local allocated port */
   struct in_addr remote_ipaddr;		/* remote IP */
   int  remote_port;				/* remote port */
   time_t timestamp;				/* last 'stream alive' TS */
   int  opposite_entry;				/* 0 based index of opposite entry */
} rtp_proxytable_t;

/*
 * RTP relay
 */
int  rtp_relay_init(void);
int  rtp_relay_start_fwd (osip_call_id_t *callid, client_id_t client_id,
                          int rtp_direction, int call_direction, int media_stream_no,
                          struct in_addr local_ipaddr, int *local_port,
                          struct in_addr remote_ipaddr, int remote_port,
                          int dejitter, int cseq);
int  rtp_relay_stop_fwd (osip_call_id_t *callid, int rtp_direction,
                         int media_stream_no, int cseq, int nolock);

#define NOLOCK_FDSET	1
#define LOCK_FDSET	0

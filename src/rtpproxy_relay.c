/*
    Copyright (C) 2003-2005  Thomas Ries <tries@gmx.net>

    This file is part of Siproxd.

    Siproxd is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Siproxd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warrantry of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Siproxd; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
*/

#include "config.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#ifdef HAVE_PTHREAD_SETSCHEDPARAM
   #include <sched.h>
#endif

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "rtpproxy.h"
#include "log.h"

#if !defined(SOL_IP)
#define SOL_IP IPPROTO_IP
#endif

static char const ident[]="$Id$";

/* configuration storage */
extern struct siproxd_config configuration;

/*
 * table to remember all active rtp proxy streams
 */
rtp_proxytable_t rtp_proxytable[RTPPROXY_SIZE];

/*
 * Mutex for thread synchronization (locking when accessing common 
 * data structures -> rtp_proxytable[]).
 *
 * use a 'fast' mutex for synchronizing - as these are portable... 
 */
static pthread_mutex_t rtp_proxytable_mutex = PTHREAD_MUTEX_INITIALIZER;

/* thread id of RTP proxy */
static pthread_t rtpproxy_tid=0;

/* master fd_set */
static fd_set master_fdset;
static int    master_fd_max;

/*
 * RTP buffers for dejitter
 */
typedef char rtp_buff_t[RTP_BUFFER_SIZE];
typedef struct {
   void *next;				/* next free or next que element */
   int socked;				/* socket number */
   size_t message_len;			/* length of message */
   int flags;				/* flags */
   struct sockaddr_in dst_addr;		/* where shall i send */
   struct timeval transm_time;		/* when shall i send */
   rtp_proxytable_t *errret;		/* deliver error status */
   rtp_buff_t rtp_buff;			/* Data storage */
} rtp_delayed_message;


/*
 * table to buffer date for dejitter function
 */
#define NUMBER_OF_BUFFER (10*RTPPROXY_SIZE)
static rtp_delayed_message rtp_buffer_area[NUMBER_OF_BUFFER];

static rtp_delayed_message *free_memory;
static rtp_delayed_message *msg_que;

static struct timeval current_tv;
static struct timeval minstep;

/*
 * forward declarations of internal functions
 */
static void *rtpproxy_main(void *i);
static int rtp_recreate_fdset(void);
void rtpproxy_kill( void );
static void sighdl_alm(int sig) {/* just wake up from select() */};

/* dejitter */
static void rtp_buffer_init ();
static void add_time_values(const struct timeval *a,
                            const struct timeval *b, struct timeval *r);
static void sub_time_values(const struct timeval *a, const struct timeval *b,
                            struct timeval *r);
static int  cmp_time_values(const struct timeval *a, const struct timeval *b);
static double make_double_time(const struct timeval *tv);
static void send_top_of_que(void);
static void delayedsendto(int s, const void *msg, size_t len, int flags,
                          const struct sockaddr_in *to,
                          const struct timeval *tv, rtp_proxytable_t *errret);
static void cancelmessages(rtp_proxytable_t *dropentry);
static void flushbuffers(void);
static int  delay_of_next_transmission(struct timeval *tv);
static void split_double_time(double d, struct timeval *tv);
static void init_calculate_transmit_time(timecontrol_t *tc, int dejitter);
static int  fetch_missalign_long_network_oder(char *where);
static void calculate_transmit_time(rtp_buff_t *rtp_buff, timecontrol_t *tc,
                                    const struct timeval *input_tv,
                                    struct timeval *ttv);

/* */
static void match_socket (int rtp_proxytable_idx);
static void error_handler (int rtp_proxytable_idx, int socket_type);


/*
 * initialize and create rtp_relay proxy thread
 *
 * RETURNS
 *	STS_SUCCESS on success
 */
int rtp_relay_init( void ) {
   int sts;
   int arg=0;
   struct sigaction sigact;

   rtp_buffer_init();

   atexit(rtpproxy_kill);  /* cancel RTP thread at exit */

   /* clean proxy table */
   memset (rtp_proxytable, 0, sizeof(rtp_proxytable));

   /* initialize fd set for RTP proxy thread */
   FD_ZERO(&master_fdset); /* start with an empty fdset */
   master_fd_max=-1;

   /* install signal handler for SIGALRM - used to wake up
      the rtpproxy thread from select() hibernation */
   sigact.sa_handler = sighdl_alm;
   sigemptyset(&sigact.sa_mask);
   sigact.sa_flags=0;
   sigaction(SIGALRM, &sigact, NULL);

   DEBUGC(DBCLASS_RTP,"create thread");
   sts=pthread_create(&rtpproxy_tid, NULL, rtpproxy_main, (void *)&arg);
   DEBUGC(DBCLASS_RTP,"created, sts=%i", sts);

   /* set realtime scheduling - if started by root */
#ifdef HAVE_PTHREAD_SETSCHEDPARAM
   {
      int uid,euid;
      struct sched_param schedparam;

#ifndef _CYGWIN
      uid=getuid();
      euid=geteuid();
      DEBUGC(DBCLASS_RTP,"uid=%i, euid=%i", uid, euid);
      if (uid != euid) seteuid(0);

      if (geteuid()==0) {
#endif

#if defined(HAVE_SCHED_GET_PRIORITY_MAX) && defined(HAVE_SCHED_GET_PRIORITY_MIN)
         int pmin, pmax;
         /* place ourself at 1/3 of the available priority space */
         pmin=sched_get_priority_min(SCHED_RR);
         pmax=sched_get_priority_max(SCHED_RR);
         schedparam.sched_priority=pmin+(pmax-pmin)/3;
         DEBUGC(DBCLASS_RTP,"pmin=%i, pmax=%i, using p=%i", pmin, pmax,
                schedparam.sched_priority);
#else
         /* just taken a number out of thin air */
         schedparam.sched_priority=10;
         DEBUGC(DBCLASS_RTP,"using p=%i", schedparam.sched_priority);
#endif
         sts=pthread_setschedparam(rtpproxy_tid, SCHED_RR, &schedparam);
         if (sts != 0) {
            ERROR("pthread_setschedparam failed: %s", strerror(errno));
         }
#ifndef _CYGWIN
      } else {
         INFO("Unable to use realtime scheduling for RTP proxy");
         INFO("You may want to start siproxd as root and switch UID afterwards");
      }
      if (uid != euid)  seteuid(euid);
#endif
   }
#endif

   return STS_SUCCESS;
}


/*
 * main() of rtpproxy
 */
static void *rtpproxy_main(void *arg) {
   fd_set fdset;
   int fd_max;
   int i;
   int num_fd;
   static rtp_buff_t rtp_buff;
   int count;
   struct timeval last_tv ;
   struct timeval sleep_tv ;
   struct timeval input_tv ;
   struct timezone tz ;

   memcpy(&fdset, &master_fdset, sizeof(fdset));
   fd_max=master_fd_max;
   last_tv.tv_sec = 0;
   last_tv.tv_usec = 0;

   /* loop forever... */
   for (;;) {

      if (!delay_of_next_transmission(&sleep_tv))
      {
//        DEBUGC(DBCLASS_RTP, "rtp que empty") ;
        sleep_tv.tv_sec = 5;
        sleep_tv.tv_usec = 0;
      };

      num_fd=select(fd_max+1, &fdset, NULL, NULL, &sleep_tv);
      gettimeofday(&input_tv,&tz);
      current_tv = input_tv;

      /*
       * Send delayed Packets
       */
      flushbuffers();

      /* exit point for this thread in case of program terminaction */
      pthread_testcancel();
      if ((num_fd<0) && (errno==EINTR)) {
         /*
          * wakeup due to a change in the proxy table:
          * lock mutex, copy master FD set and unlock
          */
         pthread_mutex_lock(&rtp_proxytable_mutex);
         memcpy(&fdset, &master_fdset, sizeof(fdset));
         fd_max=master_fd_max;
         pthread_mutex_unlock(&rtp_proxytable_mutex);
         continue;
      }


      /*
       * LOCK the MUTEX
       */
      pthread_mutex_lock(&rtp_proxytable_mutex);

      /* check for data available and send to destination */
      for (i=0;(i<RTPPROXY_SIZE) && (num_fd>0);i++) {
         /*
          * RTCP control socket
          */
         if ( (rtp_proxytable[i].rtp_con_rx_sock != 0) &&
            FD_ISSET(rtp_proxytable[i].rtp_con_rx_sock, &fdset) ) {
            /* yup, have some data to send */
            num_fd--;

            /* read from sock rtp_proxytable[i].rtp_con_rx_sock */
            count=read(rtp_proxytable[i].rtp_con_rx_sock, rtp_buff, RTP_BUFFER_SIZE);

            /* check if something went banana */
            if (count < 0) error_handler(i,1) ;

            /* Buffer really full? This may indicate a too small buffer! */
            if (count == RTP_BUFFER_SIZE) {
               LIMIT_LOG_RATE(30) {
                  WARN("received an RTCP datagram bigger than buffer size");
               }
            }

            /*
             * forwarding an RTCP packet only makes sense if we really
             * have got some data in it (count > 0)
             */
            if (count > 0) {
               /* find the corresponding TX socket */
               if (rtp_proxytable[i].rtp_con_tx_sock == 0) match_socket(i);

               if (rtp_proxytable[i].rtp_con_tx_sock != 0) {
                  struct sockaddr_in dst_addr;
                  struct timeval ttv ;

                  add_time_values(&(rtp_proxytable[i].tc.dejitter_tv),
                                  &input_tv,&ttv) ;

                  /* write to dest via socket rtp_con_tx_sock */
                  dst_addr.sin_family = AF_INET;
                  memcpy(&dst_addr.sin_addr.s_addr,
                         &rtp_proxytable[i].remote_ipaddr,
                         sizeof(struct in_addr));
                  dst_addr.sin_port= htons(rtp_proxytable[i].remote_port+1);
                  delayedsendto(rtp_proxytable[i].rtp_con_tx_sock, rtp_buff,
                                count, 0, &dst_addr, &ttv, &rtp_proxytable[i]) ;
               }
            } /* count > 0 */
            /* update timestamp of last usage for both (RX and TX) entries.
             * This allows silence (no data) on one stream without breaking
             * the connection after the RTP timeout */
            rtp_proxytable[i].timestamp=current_tv.tv_sec;
            if (rtp_proxytable[i].opposite_entry > 0) {
               rtp_proxytable[rtp_proxytable[i].opposite_entry-1].timestamp=
                  current_tv.tv_sec;
            }
         } /* if */

         /*
          * RTP data stream
          */
         if ( (rtp_proxytable[i].rtp_rx_sock != 0) &&
            FD_ISSET(rtp_proxytable[i].rtp_rx_sock, &fdset) ) {
            /* yup, have some data to send */
            num_fd--;

            /* read from sock rtp_proxytable[i].rtp_rx_sock */
            count=read(rtp_proxytable[i].rtp_rx_sock, rtp_buff, RTP_BUFFER_SIZE);

            /* check if something went banana */
            if (count < 0) error_handler (i,0);

            /* Buffer really full? This may indicate a too small buffer! */
            if (count == RTP_BUFFER_SIZE) {
               LIMIT_LOG_RATE(30) {
                  WARN("received an RTP datagram bigger than buffer size");
               }
            }

            /*
             * forwarding an RTP packet only makes sense if we really
             * have got some data in it (count > 0)
             */
            if (count > 0) {
               /* find the corresponding TX socket */
               if (rtp_proxytable[i].rtp_tx_sock == 0) match_socket(i);

               if (rtp_proxytable[i].rtp_tx_sock != 0) {
                  struct sockaddr_in dst_addr;
                  struct timeval ttv;

                  calculate_transmit_time(&rtp_buff,&(rtp_proxytable[i].tc),
                                          &input_tv,&ttv) ;

                  /* write to dest via socket rtp_tx_sock */
                  dst_addr.sin_family = AF_INET;
                  memcpy(&dst_addr.sin_addr.s_addr,
                         &rtp_proxytable[i].remote_ipaddr,
                         sizeof(struct in_addr));
                  dst_addr.sin_port= htons(rtp_proxytable[i].remote_port);
                  delayedsendto(rtp_proxytable[i].rtp_tx_sock, rtp_buff,
                                count, 0, &dst_addr, &ttv, &rtp_proxytable[i]);
               }
            } /* count > 0 */
            /* update timestamp of last usage for both (RX and TX) entries.
             * This allows silence (no data) on one stream without breaking
             * the connection after the RTP timeout */
            rtp_proxytable[i].timestamp=current_tv.tv_sec;
            if (rtp_proxytable[i].opposite_entry > 0) {
               rtp_proxytable[rtp_proxytable[i].opposite_entry-1].timestamp=
                  current_tv.tv_sec;
            }
         } /* if */
      } /* for i */

      /*
       * age and clean rtp_proxytable (check every 10 seconds)
       */
      if (current_tv.tv_sec > last_tv.tv_sec) {
         last_tv.tv_sec = current_tv.tv_sec + 10 ;
         for (i=0;i<RTPPROXY_SIZE; i++) {
            if ( (rtp_proxytable[i].rtp_rx_sock != 0) &&
                 ((rtp_proxytable[i].timestamp+configuration.rtp_timeout) < 
                   current_tv.tv_sec)) {
               osip_call_id_t callid;

               /* this one has expired, clean it up */
               callid.number=rtp_proxytable[i].callid_number;
               callid.host=rtp_proxytable[i].callid_host;
               cancelmessages(&rtp_proxytable[i]);
               INFO("RTP stream %s@%s (media=%i) has expired",
                    callid.number, callid.host,
                    rtp_proxytable[i].media_stream_no);
               DEBUGC(DBCLASS_RTP,"RTP stream rx_sock=%i tx_sock=%i "
                      "%s@%s (idx=%i) has expired",
                      rtp_proxytable[i].rtp_rx_sock,
                      rtp_proxytable[i].rtp_tx_sock,
                      callid.number, callid.host, i);
               /* Don't lock the mutex, as we own the lock already here */
               /* Only stop the stream we caught is timeout and not everything.
                * This may be a multiple stream conversation (audio/video) and
                * just one (unused?) has timed out. Seen with VoIPEX PBX! */
               rtp_relay_stop_fwd(&callid, rtp_proxytable[i].direction,
                                        rtp_proxytable[i].media_stream_no, 1);
            } /* if */
         } /* for i */
      } /* if (t>...) */

      /* copy master FD set */
      memcpy(&fdset, &master_fdset, sizeof(fdset));
      fd_max=master_fd_max;

      /*
       * UNLOCK the MUTEX
       */
      pthread_mutex_unlock(&rtp_proxytable_mutex);
   } /* for(;;) */

   return NULL;
}


/*
 * start an rtp stream on the proxy
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int rtp_relay_start_fwd (osip_call_id_t *callid, char *client_id,
                         int rtp_direction,
                         int media_stream_no, struct in_addr local_ipaddr,
                         int *local_port, struct in_addr remote_ipaddr,
                         int remote_port, int dejitter) {
   static int prev_used_port = 0;
   int num_ports;
   int i2, i, j;
   int sock, port;
   int sock_con;
   int freeidx;
   int sts=STS_SUCCESS;
   int tos;
   osip_call_id_t cid;

   if (callid == NULL) {
      ERROR("rtp_relay_start_fwd: callid is NULL!");
      return STS_FAILURE;
   }

   if (client_id == NULL) {
      ERROR("rtp_relay_start_fwd: did not get a client ID!");
      return STS_FAILURE;
   }

   /*
    * life insurance: check size of received call_id strings
    * I don't know what the maximum allowed size within SIP is,
    * so if this test fails maybe it's just necessary to increase
    * the constants CALLIDNUM_SIZE and/or CALLIDHOST_SIZE.
    */
   if (callid->number && (strlen(callid->number) >= CALLIDNUM_SIZE)) {
      ERROR("rtp_relay_start_fwd: received callid number [%s] "
            "has too many characters (%ld, max=%i)",
            callid->number, (long)strlen(callid->number),CALLIDNUM_SIZE);
      return STS_FAILURE;
   }
   if (callid->host && (strlen(callid->host) >= CALLIDHOST_SIZE)) {
      ERROR("rtp_relay_start_fwd: received callid host [%s] "
            "has too many characters (%ld, max=%i)",
            callid->host, (long)strlen(callid->host),CALLIDHOST_SIZE);
      return STS_FAILURE;
   }
   if (client_id && (strlen(client_id) >= CLIENT_ID_SIZE)) {
      ERROR("rtp_relay_start_fwd: client ID [%s] has too many characters "
            "(%ld, max=%i)",
            client_id, (long)strlen(client_id),CLIENT_ID_SIZE);
      return STS_FAILURE;
   }

   DEBUGC(DBCLASS_RTP,"rtp_relay_start_fwd: starting RTP proxy "
          "stream for: %s@%s[%s] (%s) #=%i",
          callid->number, callid->host, client_id,
          ((rtp_direction == DIR_INCOMING) ? "incoming RTP" : "outgoing RTP"),
          media_stream_no);

   /* lock mutex */
   #define return is_forbidden_in_this_code_section
   pthread_mutex_lock(&rtp_proxytable_mutex);
   /*
    * !! We now have a locked MUTEX! It is forbidden to return() from
    * !! here up to the end of this funtion where the MUTEX is
    * !! unlocked again.
    * !! Per design, a mutex is locked (for one purpose) at *exactly one*
    * !! place in the code and unlocked also at *exactly one* place.
    * !! this minimizes the risk of deadlocks.
    */

   /*
    * figure out, if this is an request to start an RTP proxy stream
    * that is already existing (identified by SIP Call-ID, direction,
    * media_stream_no and some other client unique thing).
    * This can be due to UDP repetitions of the INVITE request...
    */
   for (i=0; i<RTPPROXY_SIZE; i++) {
      cid.number = rtp_proxytable[i].callid_number;
      cid.host   = rtp_proxytable[i].callid_host;
      if (rtp_proxytable[i].rtp_rx_sock &&
         (compare_callid(callid, &cid) == STS_SUCCESS) &&
         (rtp_proxytable[i].direction == rtp_direction) &&
         (rtp_proxytable[i].media_stream_no == media_stream_no) &&
         (strcmp(rtp_proxytable[i].client_id, client_id) == 0)) {
         /*
          * The RTP port number reported by the UA MAY change
          * for a given media stream
          * (seen with KPhone during HOLD/unHOLD)
          * Also the destination IP may change during a re-Invite
          * (seen with Sipphone.com, re-Invites when using
          * the SIP - POTS gateway [SIP Minutes]
          */
         /* Port number */
         if (rtp_proxytable[i].remote_port != remote_port) {
            DEBUGC(DBCLASS_RTP,"RTP port number changed %i -> %i",
                   rtp_proxytable[i].remote_port, remote_port);
            rtp_proxytable[i].remote_port = remote_port;
         }
         /* IP address */
         if (memcmp(&rtp_proxytable[i].remote_ipaddr, &remote_ipaddr,
                    sizeof(remote_ipaddr))) {
            DEBUGC(DBCLASS_RTP,"RTP IP address changed to %s",
                   utils_inet_ntoa(remote_ipaddr));
            memcpy (&rtp_proxytable[i].remote_ipaddr, &remote_ipaddr,
                     sizeof(remote_ipaddr));
         }

         /*
          *  set up timecrontrol for dejitter function
          */
         init_calculate_transmit_time(&rtp_proxytable[i].tc,dejitter);


         /* return the already known local port number */
         DEBUGC(DBCLASS_RTP,"RTP stream already active idx=%i (remaddr=%s, "
                "remport=%i, lclport=%i, id=%s, #=%i)",
                i, utils_inet_ntoa(remote_ipaddr),
                rtp_proxytable[i].remote_port,
                rtp_proxytable[i].local_port,
                rtp_proxytable[i].callid_number,
                rtp_proxytable[i].media_stream_no);
         *local_port=rtp_proxytable[i].local_port;
         sts = STS_SUCCESS;
	 goto unlock_and_exit;
      } /* if already active */
   } /* for */


   /*
    * find first free slot in rtp_proxytable
    */
   freeidx=-1;
   for (j=0; j<RTPPROXY_SIZE; j++) {
      if (rtp_proxytable[j].rtp_rx_sock==0) {
         freeidx=j;
         break;
      }
   }

   /* rtp_proxytable port pool full? */
   if (freeidx == -1) {
      ERROR("rtp_relay_start_fwd: rtp_proxytable is full!");
      sts = STS_FAILURE;
      goto unlock_and_exit;
   }

   /* TODO: randomize the port allocation - start at a random offset to
         search in the allowed port range (so some modulo stuff w/
         random start offset
         - for i=x to (p1-p0)+x; p=p0+mod(x,p1-p0) */

   /* find a local port number to use and bind to it */
   sock=0;	/* RTP socket */
   sock_con=0;	/* RTCP socket */
   port=0;

   if ((prev_used_port < configuration.rtp_port_low) ||
       (prev_used_port > configuration.rtp_port_high)) {
      prev_used_port = configuration.rtp_port_high;
   }

   num_ports = configuration.rtp_port_high - configuration.rtp_port_low + 1;
   for (i2 = (prev_used_port - configuration.rtp_port_low + 1);
        i2 < (num_ports + prev_used_port - configuration.rtp_port_low + 1);
        i2++) {
      i = (i2%num_ports) + configuration.rtp_port_low;

      /* only allow even port numbers */
      if ((i % 2) != 0) continue;

      for (j=0; j<RTPPROXY_SIZE; j++) {
         /* check if port already in use */
         if (memcmp(&rtp_proxytable[j].local_ipaddr,
                     &local_ipaddr, sizeof(struct in_addr))== 0) {
            if (rtp_proxytable[j].local_port == i) break;
            if (rtp_proxytable[j].local_port == i + 1) break;
            if (rtp_proxytable[j].local_port + 1 == i) break;
            if (rtp_proxytable[j].local_port + 1 == i + 1) break;
          }
      }

      /* port is available, try to allocate */
      if (j == RTPPROXY_SIZE) {
         port=i;
         sock=sockbind(local_ipaddr, port, 0);	/* RTP */

         if (sock) {
            sock_con=sockbind(local_ipaddr, port+1, 0);	/* RTCP */
            /* if success break, else try further on */
            if (sock_con) break;
            sts = close(sock);
            DEBUGC(DBCLASS_RTP,"closed socket %i [%i] for RTP stream because "
                               "cant get pair sts=%i",
                               sock, i, sts);
         } /* if sock */
      } /* if j */

   } /* for i */
   prev_used_port = port+1;

   DEBUGC(DBCLASS_RTP,"rtp_relay_start_fwd: addr=%s, port=%i, sock=%i, "
          "freeidx=%i, input data dejitter buffer=%i usec", 
          utils_inet_ntoa(local_ipaddr), port, sock, freeidx, dejitter);

   /* found an unused port? No -> RTP port pool fully allocated */
   if ((port == 0) || (sock == 0) || (sock_con == 0)) {
      ERROR("rtp_relay_start_fwd: no RTP port available or bind() failed");
      sts = STS_FAILURE;
      goto unlock_and_exit;
   }

   /*&&&: do RTP and RTCP both set DSCP value? */
   /* set DSCP value, need to be ROOT */
   if (configuration.rtp_dscp) {
      int uid,euid;
      uid=getuid();
      euid=geteuid();
      DEBUGC(DBCLASS_RTP,"uid=%i, euid=%i", uid, euid);
      if (uid != euid) seteuid(0);
      if (geteuid()==0) {
         /* now I'm root */
         if (!(configuration.rtp_dscp & ~0x3f)) {
            tos = (configuration.rtp_dscp << 2) & 0xff;
            if(setsockopt(sock, SOL_IP, IP_TOS, &tos, sizeof(tos))) {
               ERROR("rtp_relay_start_fwd: setsockopt() failed while "
                     "setting DSCP value: %s", strerror(errno));
            }
         } else {
            ERROR("rtp_relay_start_fwd: Invalid DSCP value %d",
                  configuration.rtp_dscp);
            configuration.rtp_dscp = 0; /* inhibit further attempts */
         }
      } else {
         /* could not get root */
         WARN("siproxd not started as root - cannot set DSCP value");
         configuration.rtp_dscp = 0; /* inhibit further attempts */
      }
      /* drop privileges */
      if (uid != euid) seteuid(euid);
   }

   /* write entry into rtp_proxytable slot (freeidx) */
   rtp_proxytable[freeidx].rtp_rx_sock=sock;
   rtp_proxytable[freeidx].rtp_con_rx_sock = sock_con;

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

   if (client_id) {
      strcpy(rtp_proxytable[freeidx].client_id, client_id);
   } else {
      rtp_proxytable[freeidx].client_id[0]='\0';
   }

   rtp_proxytable[freeidx].direction = rtp_direction;
   rtp_proxytable[freeidx].media_stream_no = media_stream_no;
   memcpy(&rtp_proxytable[freeidx].local_ipaddr,
          &local_ipaddr, sizeof(struct in_addr));
   rtp_proxytable[freeidx].local_port=port;
   memcpy(&rtp_proxytable[freeidx].remote_ipaddr,
          &remote_ipaddr, sizeof(struct in_addr));
   rtp_proxytable[freeidx].remote_port=remote_port;
   time(&rtp_proxytable[freeidx].timestamp);

   /*
   *  set up timecrontrol for dejitter function
   */
   init_calculate_transmit_time(&rtp_proxytable[freeidx].tc,dejitter);

   *local_port=port;

   /* call to firewall API: RTP port */
   fwapi_start_rtp(rtp_proxytable[freeidx].direction,
                   rtp_proxytable[freeidx].local_ipaddr,
                   rtp_proxytable[freeidx].local_port,
                   rtp_proxytable[freeidx].remote_ipaddr,
                   rtp_proxytable[freeidx].remote_port);
   /* call to firewall API: RTCP port */
   fwapi_start_rtp(rtp_proxytable[freeidx].direction,
                   rtp_proxytable[freeidx].local_ipaddr,
                   rtp_proxytable[freeidx].local_port + 1,
                   rtp_proxytable[freeidx].remote_ipaddr,
                   rtp_proxytable[freeidx].remote_port + 1);

   /* prepare FD set for next select operation */
   rtp_recreate_fdset();

   /* wakeup/signal rtp_proxythread from select() hibernation */
   if (!pthread_equal(rtpproxy_tid, pthread_self()))
      pthread_kill(rtpproxy_tid, SIGALRM);

//&&&
   DEBUGC(DBCLASS_RTP,"rtp_relay_start_fwd: started RTP proxy "
          "stream for: %s@%s[%s] (%s) #=%i idx=%i",
          rtp_proxytable[freeidx].callid_number,
          rtp_proxytable[freeidx].callid_host,
          rtp_proxytable[freeidx].client_id,
          ((rtp_proxytable[freeidx].direction == DIR_INCOMING) ? "incoming RTP" : "outgoing RTP"),
          rtp_proxytable[freeidx].media_stream_no, freeidx);

unlock_and_exit:
   /* unlock mutex */
   pthread_mutex_unlock(&rtp_proxytable_mutex);
   #undef return

   return sts;
}


/*
 * stop a rtp stream on the proxy
 *
 * if media_stream_no == -1, all media streams will be stopped,
 * otherwise only the specified one.
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int rtp_relay_stop_fwd (osip_call_id_t *callid,
                        int rtp_direction,
                        int media_stream_no, int nolock) {
   int i, sts;
   int retsts=STS_SUCCESS;
   int got_match=0;
   osip_call_id_t cid;
 
   if (callid == NULL) {
      ERROR("rtp_relay_stop_fwd: callid is NULL!");
      return STS_FAILURE;
   }

   DEBUGC(DBCLASS_RTP,"rtp_relay_stop_fwd: stopping RTP proxy "
          "stream for: %s@%s (%s) (nolock=%i)",
          callid->number, callid->host,
          ((rtp_direction == DIR_INCOMING) ? "incoming" : "outgoing"),
          nolock);

   /*
    * lock mutex - only if not requested to skip the lock.
    * this is needed as we are also called from within
    * the RTP thread itself - and there we already own the lock.
    */
   #define return is_forbidden_in_this_code_section
   if (nolock == 0) {
      pthread_mutex_lock(&rtp_proxytable_mutex);
      /*
       * !! We now have a locked MUTEX! It is forbidden to return() from
       * !! here up to the end of this funtion where the MUTEX is
       * !! unlocked again.
       * !! Per design, a mutex is locked (for one purpose) at *exactly one*
       * !! place in the code and unlocked also at *exactly one* place.
       * !! this minimizes the risk of deadlocks.
       */
   }
   /* 
   * wakeup/signal rtp_proxythread from select() hibernation.
   * This must be done here before we close the socket, otherwise
   * we may get an select() error later from the proxy thread that
   * is still hibernating in select() now.
   */
   if (!pthread_equal(rtpproxy_tid, pthread_self()))
      pthread_kill(rtpproxy_tid, SIGALRM);

   /*
    * find the proper entry in rtp_proxytable
    * we need to loop the whole table, as there might be multiple
    * media streams active for the same callid (audio + video stream)
    * if media_stream_no == -1, all streams are stoppen, otherwise
    * if media_stream_no > 0 only the specified stream is stopped.
    */
   for (i=0; i<RTPPROXY_SIZE; i++) {
      cid.number = rtp_proxytable[i].callid_number;
      cid.host   = rtp_proxytable[i].callid_host;
      if (rtp_proxytable[i].rtp_rx_sock &&
         (compare_callid(callid, &cid) == STS_SUCCESS) &&
         (rtp_proxytable[i].direction == rtp_direction) &&
         ((media_stream_no < 0) ||
          (media_stream_no == rtp_proxytable[i].media_stream_no))) {
         /* close RTP sockets */
         sts = close(rtp_proxytable[i].rtp_rx_sock);
         DEBUGC(DBCLASS_RTP,"closed socket %i for RTP stream "
                "%s:%s == %s:%s  (idx=%i) sts=%i",
                rtp_proxytable[i].rtp_rx_sock,
                rtp_proxytable[i].callid_number,
                rtp_proxytable[i].callid_host,
                callid->number, callid->host, i, sts);
         if (sts < 0) {
            ERROR("Error in close(%i): %s nolock=%i %s:%s\n",
                  rtp_proxytable[i].rtp_rx_sock,
                  strerror(errno), nolock,
                  callid->number, callid->host);
         }
         /* call to firewall API (RTP port) */
         fwapi_stop_rtp(rtp_proxytable[i].direction,
                   rtp_proxytable[i].local_ipaddr,
                   rtp_proxytable[i].local_port,
                   rtp_proxytable[i].remote_ipaddr,
                   rtp_proxytable[i].remote_port);
         /* close RTCP socket */
         sts = close(rtp_proxytable[i].rtp_con_rx_sock);
         DEBUGC(DBCLASS_RTP,"closed socket %i for RTCP stream sts=%i",
                rtp_proxytable[i].rtp_con_rx_sock, sts);
         if (sts < 0) {
            ERROR("Error in close(%i): %s nolock=%i %s:%s\n",
                  rtp_proxytable[i].rtp_con_rx_sock,
                  strerror(errno), nolock,
                  callid->number, callid->host);
         }
         /* call to firewall API (RTCP port) */
         fwapi_stop_rtp(rtp_proxytable[i].direction,
                   rtp_proxytable[i].local_ipaddr,
                   rtp_proxytable[i].local_port + 1,
                   rtp_proxytable[i].remote_ipaddr,
                   rtp_proxytable[i].remote_port + 1);
         /* clean up */
         memset(&rtp_proxytable[i], 0, sizeof(rtp_proxytable[0]));
         got_match=1;
      }
   }

   /* did not find an active stream... */
   if (!got_match) {
      DEBUGC(DBCLASS_RTP,
             "rtp_relay_stop_fwd: can't find active stream for %s@%s (%s)",
             callid->number, callid->host,
             ((rtp_direction == DIR_INCOMING) ? "incoming RTP" : "outgoing RTP"));
      retsts = STS_FAILURE;
      goto unlock_and_exit;
   }


   /* prepare FD set for next select operation */
   rtp_recreate_fdset();
   

unlock_and_exit:
   /*
    * unlock mutex - only if not requested to skip the lock.
    * this is needed as we are also called from within
    * the RTP thread itself - and there we already own the lock.
    */
   if (nolock == 0) {
      pthread_mutex_unlock(&rtp_proxytable_mutex);
   }
   #undef return

   return retsts;
}


/*
 * some sockets have been newly created or removed -
 * recreate the FD set for next select operation
 *
 * RETURNS
 *	STS_SUCCESS on success (always)
 */
static int rtp_recreate_fdset(void) {
   int i;

   FD_ZERO(&master_fdset);
   master_fd_max=-1;
   for (i=0;i<RTPPROXY_SIZE;i++) {
      if (rtp_proxytable[i].rtp_rx_sock != 0) {
         /* RTP */
         FD_SET(rtp_proxytable[i].rtp_rx_sock, &master_fdset);
         if (rtp_proxytable[i].rtp_rx_sock > master_fd_max) {
            master_fd_max=rtp_proxytable[i].rtp_rx_sock;
         }
         /* RTPCP */
         FD_SET(rtp_proxytable[i].rtp_con_rx_sock, &master_fdset);
         if (rtp_proxytable[i].rtp_con_rx_sock > master_fd_max) {
            master_fd_max=rtp_proxytable[i].rtp_con_rx_sock;
         }
      }
   } /* for i */
   return STS_SUCCESS;
}


/*
 * kills the rtp_proxy thread
 *
 * RETURNS
 *	-
 */
void rtpproxy_kill( void ) {
   void *thread_status;
   osip_call_id_t cid;
   int i, sts;

   /* stop any active RTP stream */
   for (i=0;i<RTPPROXY_SIZE;i++) {
      if (rtp_proxytable[i].rtp_rx_sock != 0) {
         cid.number = rtp_proxytable[i].callid_number;
         cid.host   = rtp_proxytable[i].callid_host;
         sts = rtp_relay_stop_fwd(&cid, rtp_proxytable[i].direction,
                                  rtp_proxytable[i].media_stream_no, 0);
      }
   }
   

   /* kill the thread */
   if (rtpproxy_tid) {
      pthread_cancel(rtpproxy_tid);
      pthread_kill(rtpproxy_tid, SIGALRM);
      pthread_join(rtpproxy_tid, &thread_status);
   }

   DEBUGC(DBCLASS_RTP,"killed RTP proxy thread");
   return;
}


/***********
 * De-Jitter
 ***********/

/*
 * Initialize RTP dejitter
 */
static void rtp_buffer_init () {
   int i;
   rtp_delayed_message *m;

   memset (&rtp_buffer_area, 0, sizeof(rtp_buffer_area));
   free_memory = NULL;
   msg_que = NULL;
   for (i=0,m=&rtp_buffer_area[0];i<NUMBER_OF_BUFFER;i++,m++) {
      m->next = free_memory;
      free_memory = m;
   }
}

/*
 * Add timeval times
 */
static void add_time_values(const struct timeval *a,
                            const struct timeval *b, struct timeval *r) {
   r->tv_sec = a->tv_sec + b->tv_sec;
   r->tv_usec = a->tv_usec + b->tv_usec;
   if (r->tv_usec >= 1000000) {
      r->tv_usec -= 1000000;
      r->tv_sec++;
   }
}

/*
 * Subtract timeval values
 */
static void sub_time_values(const struct timeval *a,
                            const struct timeval *b, struct timeval *r) {
   if ((a->tv_sec < b->tv_sec) ||
       ((a->tv_sec == b->tv_sec) && (a->tv_usec < b->tv_usec))) {
      r->tv_usec = 0;
      r->tv_sec = 0;
      return;
   }
   if (a->tv_usec < b->tv_usec) {
      r->tv_sec = a->tv_sec - b->tv_sec - 1;
      r->tv_usec = a->tv_usec + 1000000 - b->tv_usec;
   } else {
      r->tv_sec = a->tv_sec - b->tv_sec;
      r->tv_usec = a->tv_usec - b->tv_usec;
   }
}

/*
 * Compare timeval values
 */
static int cmp_time_values(const struct timeval *a, const struct timeval *b) {
   if (a->tv_sec < b->tv_sec) return -1;
   if (a->tv_sec > b->tv_sec) return 1;
   if (a->tv_usec < b->tv_usec) return -1;
   if (a->tv_usec > b->tv_usec) return 1;
   return 0;
}

/*
 * Convert TIMEVAL to DOUBLE 
 */
static double make_double_time(const struct timeval *tv) {
   return 1000000.0 * tv->tv_sec + tv->tv_usec;
}

/*
 * Send Top of queue
 */
static void send_top_of_que (void) {
   rtp_delayed_message *m;
   int sts;

   if (msg_que) {
      m = msg_que;
      msg_que = m->next;
      m->next = free_memory;
      free_memory = m;

      if ((m->errret != NULL) && (m->errret->rtp_tx_sock)) {
         sts = sendto(m->socked, &(m->rtp_buff), m->message_len,
                      m->flags, (const struct sockaddr *)&(m->dst_addr),
                     (socklen_t)sizeof(m->dst_addr));
         if ((sts == -1) && (m->errret != NULL) && (errno != ECONNREFUSED)) {
            osip_call_id_t callid;

            ERROR("sendto() [%s:%i size=%i] delayed call failed: %s",
                  utils_inet_ntoa(m->errret->remote_ipaddr),
                  m->errret->remote_port, m->message_len, strerror(errno));

            /* if sendto() fails with bad filedescriptor,
             * this means that the opposite stream has been
             * canceled or timed out.
             * we should then cancel this stream as well.*/

            WARN("stopping opposite stream");

            callid.number=m->errret->callid_number;
            callid.host=m->errret->callid_host;
            /* don't lock the mutex, as we own the lock */
            if (STS_SUCCESS != rtp_relay_stop_fwd(&callid, 
                                            m->errret->direction,
                                            m->errret->media_stream_no, 1)) {
               ERROR("fatal error in delayed error close! [%s:%i size=%i]",
                     utils_inet_ntoa(m->errret->remote_ipaddr),
                     m->errret->remote_port, m->message_len);
               /* brute force protection agains looping errors */
               m->errret->rtp_rx_sock = 0;
               rtp_recreate_fdset();
            } /* if stp_stop */
         } /* if sendto fails */
      }
   } /* if (msg_que) */
}

/*
 * Delayed send
 */
static void delayedsendto(int s, const void *msg, size_t len, int flags,
                          const struct sockaddr_in *to,
                          const struct timeval *tv, rtp_proxytable_t *errret) {
   rtp_delayed_message *m;
   rtp_delayed_message **linkin;

   if (!free_memory) send_top_of_que();

   m = free_memory;

   m->socked = s;
   memcpy(&(m->rtp_buff), msg, m->message_len = len);
   m->flags = flags;
   m->dst_addr = *to;
   m->transm_time = *tv;
   m->errret = errret;

   free_memory = m->next;

   if (cmp_time_values(&current_tv,tv) >= 0) {
      m->next = msg_que;
      msg_que = m;
      send_top_of_que();
   } else {
      linkin = &msg_que;
      while ((*linkin != NULL) &&
             (cmp_time_values(&((*linkin)->transm_time),tv) < 0)) {
         linkin = (rtp_delayed_message **)&((*linkin)->next);
      }
      m->next = *linkin;
      *linkin = m;
   }
}

/*
 * Cancel a message
 */
static void cancelmessages(rtp_proxytable_t *dropentry) {
   rtp_delayed_message **linkout;
   rtp_delayed_message *m;

   linkout = &msg_que;

   while (*linkout != NULL) {
      if ((*linkout)->errret == dropentry) {
         m = *linkout;
         *linkout = m->next;
         m->next = free_memory;
         free_memory = m;
      } else {
         linkout = (rtp_delayed_message **)&((*linkout)->next);
      }
   }
}

/*
 * Flush buffers
 */
static void flushbuffers(void) {
   struct timezone tz;

   while (msg_que &&
          (cmp_time_values(&(msg_que->transm_time),&current_tv)<=0)) {
      send_top_of_que();
      gettimeofday(&current_tv,&tz);
   }
}

/*
 * Delay of next transmission
 */
static int delay_of_next_transmission(struct timeval *tv) {
   struct timezone tz ;

   if (msg_que) {
      gettimeofday(&current_tv,&tz);
      sub_time_values(&(msg_que->transm_time),&current_tv,tv);
      if (cmp_time_values(tv,&minstep)<=0) {
         *tv = minstep ;
      }
      return -1;
   }
   return 0;
}

/*
 * Convert DOUBLE time into TIMEVAL
 */
static void split_double_time(double d, struct timeval *tv) {
   tv->tv_sec = d / 1000000.0;
   tv->tv_usec = d - 1000000.0 * tv->tv_sec;
}

/*
 * Initialize calculation of transmit the frame
 */
static void init_calculate_transmit_time(timecontrol_t *tc, int dejitter) {
   struct timezone tz;

   minstep.tv_sec = 0;
   minstep.tv_usec = 6000;
   memset(tc, 0, sizeof(*tc));
   if (dejitter>0) {
      gettimeofday(&(tc->starttime),&tz);

      tc->dejitter = dejitter;
      tc->dejitter_d = dejitter;
      split_double_time(tc->dejitter_d, &(tc->dejitter_tv));
   }
}

/*
 *
 */
static int fetch_missalign_long_network_oder(char *where) {
   int i = 0;
   int k;
   int j;

   for (j=0;j<4;j++) {
      k = *where;
      i = (i<<8) | (0xFF & k);
      where ++;
   }
   return i;
}

/*
 * Calculate transmit time
 */
static void calculate_transmit_time(rtp_buff_t *rtp_buff, timecontrol_t *tc,
                                    const struct timeval *input_tv,
                                    struct timeval *ttv) {
   int    packet_time_code;
   double currenttime;
   double calculatedtime = 0;
   double calculatedtime2 = 0;
   struct timeval input_r_tv;
   struct timeval output_r_tv;

   if (!tc || !tc->dejitter) {
      *ttv = current_tv;
      return;
   }


   /* I hate this computer language ... :-/ quite confuse ! look modula */
   packet_time_code = fetch_missalign_long_network_oder(&((*rtp_buff)[4]));

/*&&&& beware, it seems that when sending RTP events (payload type
telephone-event) the timestamp does not increment and stays the same.
The sequence number however DOES increment. This could lead to confusion when
transmitting RTP events (like DTMF). How can we handle this? Check for RTP event
and then do an "educated guess" for the to-be timestamp?
*/
   if (tc->calccount == 0) {
      DEBUGC(DBCLASS_RTP, "initialise time calculatin");
      tc->starttime = *input_tv;
      tc->time_code_a = packet_time_code;
   }

   sub_time_values(input_tv,&(tc->starttime),&input_r_tv);

   calculatedtime = currenttime = make_double_time(&input_r_tv);
   if (tc->calccount < 10) {
      DEBUGC(DBCLASS_RTP, "initial data stage 1 %f usec", currenttime);
      tc->received_a = currenttime / (packet_time_code - tc->time_code_a);
   } else if (tc->calccount < 20) {
      tc->received_a = 0.95 * tc->received_a + 0.05 * currenttime /
                      (packet_time_code - tc->time_code_a);
   } else {
      tc->received_a = 0.99 * tc->received_a + 0.01 * currenttime /
                      (packet_time_code - tc->time_code_a);
   }
   if (tc->calccount > 20) {
      if (!tc->time_code_b) {
         tc->time_code_b = packet_time_code;
         tc->received_b = currenttime;
      } else if (tc->time_code_b < packet_time_code) {
         calculatedtime = tc->received_b = tc->received_b + 
                          (packet_time_code - tc->time_code_b) * tc->received_a;
         tc->time_code_b = packet_time_code;
         if (tc->calccount < 28) {
            tc->received_b = 0.90 * tc->received_b + 0.1 * currenttime;
         } else if (tc->calccount < 300) {
            tc->received_b = 0.95 * tc->received_b + 0.05 * currenttime;
         } else {
            tc->received_b = 0.99 * tc->received_b + 0.01 * currenttime;
         }
      } else {
         calculatedtime = tc->received_b + 
                          (packet_time_code - tc->time_code_b) * tc->received_a;
      }
   }
   tc->received_c = currenttime;
   tc->time_code_c = packet_time_code;

   if (tc->calccount < 30) {
      /*
       * But in the start phase,
       * we asume every packet as not delayed.
       */
      calculatedtime = currenttime;
   }

   /*
   ** theoretical value for F1000 Phone
   */
   //calculatedtime = (tc->received_a = 125.) * packet_time_code;

   tc->calccount ++;
   calculatedtime += tc->dejitter_d;

   if (calculatedtime < currenttime) {
      calculatedtime = currenttime;
   } else if (calculatedtime > currenttime + 2.* tc->dejitter_d) {
      calculatedtime = currenttime + 2.* tc->dejitter_d;
   }

   /* every 500 counts show statistics */
   if (tc->calccount % 500 == 0) {
      DEBUGC(DBCLASS_RTPBABL, "currenttime = %f", currenttime);
      DEBUGC(DBCLASS_RTPBABL, "packetcode  = %i", packet_time_code);
      DEBUGC(DBCLASS_RTPBABL, "timecodes %i, %i, %i",
             tc->time_code_a, tc->time_code_b, tc->time_code_c);
      DEBUGC(DBCLASS_RTPBABL, "measuredtimes %f usec, %f usec, %f usec",
             tc->received_a, tc->received_b, tc->received_c);
      DEBUGC(DBCLASS_RTPBABL, "p2 - p1 = (%i,%f usec)",
             tc->time_code_b - tc->time_code_a,
             tc->received_b - tc->received_a);
      if (tc->time_code_c) {
         DEBUGC(DBCLASS_RTPBABL, "p3 - p2 = (%i,%f usec)",
                tc->time_code_c - tc->time_code_b,
                tc->received_c - tc->received_b);
      }
      DEBUGC(DBCLASS_RTPBABL, "calculatedtime = %f", calculatedtime);
      if (calculatedtime2) {
         DEBUGC(DBCLASS_RTPBABL, "calculatedtime2 = %f", calculatedtime2);
      }
      DEBUGC(DBCLASS_RTPBABL, "transmtime = %f (%f)", calculatedtime / 
             (160. * tc->received_a) - packet_time_code / 160,
             currenttime / (160. * tc->received_a) - 
             packet_time_code / 160);
      DEBUGC(DBCLASS_RTPBABL, "synthetic latency = %f, %f, %f, %i, %i",
             calculatedtime-currenttime, calculatedtime,
             currenttime, packet_time_code, 
             packet_time_code / 160);
   }

   split_double_time(calculatedtime, &output_r_tv);
   add_time_values(&output_r_tv,&(tc->starttime),ttv);
}

/*
 * match_socket
 * matches and cross connects two rtp_proxytable entries
 * (corresponds to the two data directions of one RTP stream)
 */
static void match_socket (int rtp_proxytable_idx) {
   int j;
   int rtp_direction = rtp_proxytable[rtp_proxytable_idx].direction;
   int media_stream_no = rtp_proxytable[rtp_proxytable_idx].media_stream_no;
/*chnnel   int channel = rtp_proxytable[rtp_proxytable_idx].channel;*/
   osip_call_id_t callid;

   callid.number = rtp_proxytable[rtp_proxytable_idx].callid_number;
   callid.host = rtp_proxytable[rtp_proxytable_idx].callid_host;

   for (j=0;(j<RTPPROXY_SIZE);j++) {
      osip_call_id_t cid;
      cid.number = rtp_proxytable[j].callid_number;
      cid.host = rtp_proxytable[j].callid_host;

      /* match on:
       * - same call ID
       * - same media stream
       * - opposite direction
       * - different client ID
       */
      if ( (rtp_proxytable[j].rtp_rx_sock != 0) &&
           (compare_callid(&callid, &cid) == STS_SUCCESS) &&
           (media_stream_no == rtp_proxytable[j].media_stream_no) &&
           (rtp_direction != rtp_proxytable[j].direction) /* channel: &&
           (channel == rtp_proxytable[j].channel)*/ ) {
         rtp_proxytable[rtp_proxytable_idx].rtp_tx_sock = rtp_proxytable[j].rtp_rx_sock;
         rtp_proxytable[rtp_proxytable_idx].rtp_con_tx_sock = rtp_proxytable[j].rtp_con_rx_sock;
         DEBUGC(DBCLASS_RTP, "connected entry %i (fd=%i) <-> entry %i (fd=%i)",
                             j, rtp_proxytable[j].rtp_rx_sock,
                             rtp_proxytable_idx,
                             rtp_proxytable[rtp_proxytable_idx].rtp_rx_sock);
         break;
      }
   }
}

/*
 * error_handler
 *
 * rtp_proxytable_idx:	index into the rtp_proxytable array
 * socket_type: 	1 - RTCP, 0 - RTP
 */
static void error_handler (int rtp_proxytable_idx, int socket_type) {
   /*
    * It has been seen on linux 2.2.x systems that for some
    * reason (ICMP issue? -> below) inside the RTP relay, select()
    * claims that a certain file descriptor has data available to
    * read, a subsequent call to read() or recv() then does block!!
    * So lets make the FD's we are going to use non-blocking, so
    * we will at least survive and not run into a deadlock.
    *
    * We catch this here with this workaround (pronounce "HACK")
    * and hope that next time we pass by it will be ok again.
    */
   if (errno == EAGAIN) {
      /* I may want to remove this WARNing */
      WARN("read() [fd=%i, %s:%i] would block, but select() "
           "claimed to be readable!",
           socket_type ? rtp_proxytable[rtp_proxytable_idx].rtp_rx_sock : 
                         rtp_proxytable[rtp_proxytable_idx].rtp_con_rx_sock,
           utils_inet_ntoa(rtp_proxytable[rtp_proxytable_idx].local_ipaddr),
           rtp_proxytable[rtp_proxytable_idx].local_port + socket_type);
   }

   /*
    * I *MAY* receive ICMP destination unreachable messages when I
    * try to send RTP traffic to a destination that is in HOLD
    * (better: is not listening on the UDP port where I send
    * my RTP data to).
    * So I should *not* do this - or ignore errors originating
    * by this -> ECONNREFUSED
    *
    * Note: This error is originating from a previous send() on the
    *       same socket and has nothing to do with the read() we have
    *       done above!
    */
   if (errno != ECONNREFUSED) {
      /* some other error that I probably want to know about */
      int j;
      WARN("read() [fd=%i, %s:%i] returned error [%i:%s]",
          socket_type ? rtp_proxytable[rtp_proxytable_idx].rtp_rx_sock : 
                        rtp_proxytable[rtp_proxytable_idx].rtp_con_rx_sock,
          utils_inet_ntoa(rtp_proxytable[rtp_proxytable_idx].local_ipaddr),
          rtp_proxytable[rtp_proxytable_idx].local_port + socket_type,
          errno, strerror(errno));
      for (j=0; j<RTPPROXY_SIZE;j++) {
         DEBUGC(DBCLASS_RTP, "%i - rx:%i tx:%i %s@%s dir:%i "
                "lp:%i, rp:%i rip:%s",
                j,
                socket_type ? rtp_proxytable[rtp_proxytable_idx].rtp_rx_sock : 
                              rtp_proxytable[rtp_proxytable_idx].rtp_con_rx_sock,
                socket_type ? rtp_proxytable[rtp_proxytable_idx].rtp_tx_sock : 
                              rtp_proxytable[rtp_proxytable_idx].rtp_con_tx_sock,
                rtp_proxytable[j].callid_number,
                rtp_proxytable[j].callid_host,
                rtp_proxytable[j].direction,
                rtp_proxytable[j].local_port,
                rtp_proxytable[j].remote_port,
                utils_inet_ntoa(rtp_proxytable[j].remote_ipaddr));
      } /* for j */
   } /* if errno != ECONNREFUSED */
}





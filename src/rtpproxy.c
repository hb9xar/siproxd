/*
    Copyright (C) 2002  Thomas Ries <tries@gmx.net>

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

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#include <osip/smsg.h>

#include "siproxd.h"
#include "log.h"

/* configuration storage */
extern struct siproxd_config configuration;

/* use a 'recursive mutex' for synchronizing */
pthread_mutex_t rtp_proxytable_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

/*
 * table to remember all active rtp proxy streams
 */
#define CALLID_SIZE	32
struct {
   int sock;
   char callid_number[CALLID_SIZE];
   char callid_host[CALLID_SIZE];
   struct in_addr outbound_ipaddr;
   int outboundport;
   struct in_addr inbound_client_ipaddr;
   int inbound_client_port; 
   time_t timestamp;  
} rtp_proxytable[RTPPROXY_SIZE];


/* thread id of RTP proxy */
pthread_t rtpproxy_tid;

/* master fd_set */
fd_set master_fdset;
int    master_fd_max;

/* forward declarations */
void *rtpproxy_main(void *i);
int rtp_recreate_fdset(void);
void sighdl_alm(int sig) {/* do nothing, just wake up from select() */};

/*
 * initialize and create rtp_proxy thread
 */
int rtpproxy_init( void ) {
   int sts;
   int arg=7;
   struct sigaction sigact;

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

#if 0 /* don't detach */
   sts=pthread_detach(rtpproxy_tid);
   DEBUGC(DBCLASS_RTP,"detached, sts=%i", sts);
#endif

   return 0;
}

/*
 * main() of rtpproxy
 */
void *rtpproxy_main(void *arg) {
   struct timeval tv;
   fd_set fdset;
   int fd_max;
   time_t t, last_t=0;
   int i, count;
   int num_fd;
   static int rtp_socket=0;
   call_id_t callid;
   char rtp_buff[RTP_BUFFER_SIZE];

   memcpy(&fdset, &master_fdset, sizeof(fdset));
   fd_max=master_fd_max;

/* test */
   for (;;) {

      tv.tv_sec = 5;
      tv.tv_usec = 0;

      num_fd=select(fd_max+1, &fdset, NULL, NULL, &tv);
      time(&t);

      if (configuration.rtp_proxy_enable) {

      /*
       * LOCK the MUTEX
       */
      pthread_mutex_lock(&rtp_proxytable_mutex);


      /* check for data available and send to destination */
      for (i=0;(i<RTPPROXY_SIZE) && (num_fd>0);i++) {
         if ( (rtp_proxytable[i].sock != 0) && 
	      FD_ISSET(rtp_proxytable[i].sock, &fdset) ) {
            /* yup, have some data to send */

/* don't... it is a mess on the screen...
DEBUGC(DBCLASS_RTP,"got data on sock=%i",rtp_proxytable[i].sock);
*/

	    /* read from sock rtp_proxytable[i].sock*/
            count=read(rtp_proxytable[i].sock, rtp_buff, RTP_BUFFER_SIZE);

	    /* write to dest via socket rtp_inbound*/
            sipsock_send_udp(&rtp_socket,
	                     rtp_proxytable[i].inbound_client_ipaddr,
			     rtp_proxytable[i].inbound_client_port,
			     rtp_buff, count, 0); /* don't dump it */
            /* update timestamp of last usage */
            rtp_proxytable[i].timestamp=t;

	    num_fd--;
         }
      }


      /* age and clean rtp_proxytable */
      if (t > (last_t+configuration.rtp_timeout) ) {
         last_t = t;
	 for (i=0;i<RTPPROXY_SIZE; i++) {
            if ( (rtp_proxytable[i].sock != 0) &&
		 (rtp_proxytable[i].timestamp+configuration.rtp_timeout)<t) {
               /* time one has expired, clean it up */
               callid.number=rtp_proxytable[i].callid_number;
               callid.host=rtp_proxytable[i].callid_host;
               DEBUGC(DBCLASS_RTP,"RTP stream %s@%s (idx=%i) has expired",
	              callid.number, callid.host, i);
	       rtp_stop_fwd(&callid);
	    }
	 }
      } /* if (t>...) */

      /* copy master FD set */
      memcpy(&fdset, &master_fdset, sizeof(fdset));
      fd_max=master_fd_max;

      /*
       * UNLOCK the MUTEX
       */
      pthread_mutex_unlock(&rtp_proxytable_mutex);

      } /* rtp proxy enabled? */
   } /* for(;;) */

   return NULL;
}



/*
 * helper routines to control the RTP proxy thread
 */

/*
 * start an rtp stream on the proxy
 */
int rtp_start_fwd (call_id_t *callid,
		   struct in_addr outbound_ipaddr, int *outboundport,
                   struct in_addr lcl_client_ipaddr, int lcl_clientport) {
   int i, j;
   int sock, port;
   int freeidx;
   int sts=0;

   if (configuration.rtp_proxy_enable == 0) return 0;

   if (callid == NULL) {
      ERROR("rtp_start_fwd: callid is NULL!");
      return 1;
   }

   DEBUGC(DBCLASS_RTP,"starting RTP proxy stream for: %s@%s",
          callid->number, callid->host);

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
    * that is already existing (identified by SIP Call-ID)
    * This can be due to UDP repetitions of the INVITE request...
    */
   for (j=0; j<RTPPROXY_SIZE; j++) {
      if((strcmp(rtp_proxytable[j].callid_number, callid->number)==0) &&
	 (strcmp(rtp_proxytable[j].callid_host, callid->host)==0) ) {
         /* return the already known port number */
         DEBUGC(DBCLASS_RTP,"RTP stream already active (port=%i)",
	        rtp_proxytable[j].outboundport);
	 *outboundport=rtp_proxytable[j].outboundport;
	 sts = 0;
	 goto unlock_and_exit;
      }
   }




/* TODO: randomize the port allocation - start at a random offset to
         search in the allowed port range (so some modulo stuff w/
	 random start offset 
	 - for i=x to (p1-p0)+x; p=p0+mod(x,p1-p0) */

   /* find a local outbound port number to use and bind to it*/
   sock=0;
   port=0;
   for (i=configuration.rtp_port_low; i<=configuration.rtp_port_high; i++) {
      for (j=0; j<RTPPROXY_SIZE; j++) {
         /* outbound port already in use */
         if ((memcmp(&rtp_proxytable[j].outbound_ipaddr,
	             &outbound_ipaddr, sizeof(struct in_addr))== 0) &&
	     (rtp_proxytable[j].outboundport == i) ) {

            /* if the rtp proxy stream is already active (this must then
               be a repetition of an SIP UDP INVITE packet) just pass back 
               the used port number an do nothing more */
            if((strcmp(rtp_proxytable[j].callid_number, callid->number)==0) &&
	       (strcmp(rtp_proxytable[j].callid_host, callid->host)==0) ) {
               /* return the already known port number */
               DEBUGC(DBCLASS_RTP,"RTP stream already active (port=%i)",
	              rtp_proxytable[j].outboundport);
	       *outboundport=rtp_proxytable[j].outboundport;
	       sts = 0;
	       goto unlock_and_exit;
	    }

	    break;
	 }
      }

      /* port is available, try to allocate */
      if (j == RTPPROXY_SIZE) {
         port=i;
         sock=sockbind(outbound_ipaddr, port);
         /* if success break, else try further on */
         if (sock) break;
      }
   }


   /* find first free slot in rtp_proxytable */
   freeidx=-1;
   for (j=0; j<RTPPROXY_SIZE; j++) {
      if (rtp_proxytable[j].sock==0) {
         freeidx=j;
	 break;
      }
   }

   DEBUGC(DBCLASS_RTP,"rtp_start_fwd: port=%i, sock=%i freeidx=%i",
          port, sock, freeidx);

   /* found an unused port? No -> RTP port pool fully allocated */
   if (port == 0) {
      ERROR("rtp_start_fwd: no RTP port available. Check rtp_port_* config!");
      sts = 1;
      goto unlock_and_exit;
   }

   /* could bind to desired port? */
   if (sock == 0) {
      ERROR("rtp_start_fwd: unable to allocate outbound port!");
      sts = 1;
      goto unlock_and_exit;
   }

   /* rtp_proxytable port pool full? */
   if (freeidx == -1) {
      ERROR("rtp_start_fwd: rtp_proxytable is full!");
      sts = 1;
      goto unlock_and_exit;
   }

   /* write entry into rtp_proxytable slot (freeidx) */
   rtp_proxytable[freeidx].sock=sock;
   strcpy(rtp_proxytable[freeidx].callid_number, callid->number);
   strcpy(rtp_proxytable[freeidx].callid_host, callid->host);
   memcpy(&rtp_proxytable[freeidx].outbound_ipaddr,
          &outbound_ipaddr, sizeof(struct in_addr));
   rtp_proxytable[freeidx].outboundport=port;
   memcpy(&rtp_proxytable[freeidx].inbound_client_ipaddr,
          &lcl_client_ipaddr, sizeof(struct in_addr));
   rtp_proxytable[freeidx].inbound_client_port=lcl_clientport;
   time(&rtp_proxytable[freeidx].timestamp);

   *outboundport=port;

   /* prepare FD set for next select operation */
   rtp_recreate_fdset();

/* wakeup/signal rtp_proxythread from select() hibernation */
   if (!pthread_equal(rtpproxy_tid, pthread_self()))
      pthread_kill(rtpproxy_tid, SIGALRM);

unlock_and_exit:
/* unlock mutex */
   pthread_mutex_unlock(&rtp_proxytable_mutex);
   #undef return

   return sts;
}


/*
 * stop a rtp stream on the proxy
 */
int rtp_stop_fwd (call_id_t *callid) {
   int i;
   int sts=0;

   if (configuration.rtp_proxy_enable == 0) return 0;

   if (callid == NULL) {
      ERROR("rtp_stop_fwd: callid is NULL!");
      return 1;
   }

   DEBUGC(DBCLASS_RTP,"stopping RTP proxy stream for: %s@%s",
          callid->number, callid->host);

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

   /* find the proper entry in rtp_proxytable */
   for (i=0; i<RTPPROXY_SIZE; i++) {
      if((strcmp(rtp_proxytable[i].callid_number, callid->number)==0) &&
	 (strcmp(rtp_proxytable[i].callid_host, callid->host)==0) ) {
         break;
      }
 
   }

   /* did not find an active stream... */
   if (i>= RTPPROXY_SIZE) {
      DEBUGC(DBCLASS_RTP,"rtp_stop_fwd: can't find active stream for %s@%s",
             callid->number, callid->host);
      sts = 1;
      goto unlock_and_exit;
   }


   /* close socket */
   close(rtp_proxytable[i].sock);

   /* clean slot in rtp_proxytable */
   memset(&rtp_proxytable[i], 0, sizeof(rtp_proxytable[0]));

   /* prepare FD set for next select operation */
   rtp_recreate_fdset();
   
   /* wakeup/signal rtp_proxythread from select() hibernation */
   if (!pthread_equal(rtpproxy_tid, pthread_self()))
      pthread_kill(rtpproxy_tid, SIGALRM);

unlock_and_exit:
/* unlock mutex */
   pthread_mutex_unlock(&rtp_proxytable_mutex);
   #undef return

   return sts;
}


/*
 * some sockets have been newly created or removed -
 * recreate the FD set for next select operation
 */
int rtp_recreate_fdset(void) {
   int i;

   FD_ZERO(&master_fdset);
   master_fd_max=0;
   for (i=0;i<RTPPROXY_SIZE;i++) {
      if (rtp_proxytable[i].sock != 0) {
         FD_SET(rtp_proxytable[i].sock, &master_fdset);
	 if (rtp_proxytable[i].sock > master_fd_max) {
	    master_fd_max=rtp_proxytable[i].sock;
	 }
      }
   } /* for i */
   return 0;
}


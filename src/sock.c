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

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_OSIP2
   #include <osip2/smsg.h>
#else
   #include <osip/smsg.h>
#endif

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";

/* configuration storage */
extern struct siproxd_config configuration;

static int listen_socket=0;

/*
 * binds to SIP UDP socket for listening to incoming packets
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int sipsock_listen (void) {
   struct in_addr ipaddr;

   memset(&ipaddr, 0, sizeof(struct in_addr));
   listen_socket=sockbind(ipaddr, configuration.sip_listen_port);
   if (listen_socket==0) return STS_FAILURE; /* failure*/

   INFO("listening on port %i", configuration.sip_listen_port);
   DEBUGC(DBCLASS_NET,"bound listen socket %i",listen_socket);
   return STS_SUCCESS;
}

/*
 * Wait for incoming SIP message. After a 5 sec timeout
 * this function returns with sts=0
 *
 * RETURNS >0 if data received, =0 if nothing received /T/O), -1 on error
 */
int sipsock_wait(void) {
   int sts;
   fd_set fdset;
   struct timeval timeout;

   timeout.tv_sec=5;
   timeout.tv_usec=0;

   FD_ZERO(&fdset);
   FD_SET (listen_socket, &fdset);
   sts=select (listen_socket+1, &fdset, NULL, NULL, &timeout);

   return sts;
}

/*
 * read a message from SIP listen socket (UDP datagram)
 *
 * RETURNS number of bytes read
 *         from is modified to return the sockaddr_in of the sender
 */
int sipsock_read(void *buf, size_t bufsize, struct sockaddr_in *from) {
   int count;
   socklen_t fromlen;

   fromlen=sizeof(struct sockaddr_in);
   count=recvfrom(listen_socket, buf, bufsize, 0,
                  (struct sockaddr *)from, &fromlen);

   DEBUGC(DBCLASS_NET,"received UDP packet from %s, count=%i",
          inet_ntoa(from->sin_addr), count);
   DUMP_BUFFER(DBCLASS_NETTRAF, buf, count);

   return count;
}


/*
 * sends an UDP datagram to the specified destination
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int sipsock_send_udp(int *sock, struct in_addr addr, int port,
                     char *buffer, int size, int allowdump) {
   struct sockaddr_in dst_addr;
   int sts;

   /* first time: allocate a socket for sending */
   if (*sock == 0) {
      *sock=socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if (*sock == 0) {
         ERROR("socket() call failed:%s",strerror(errno));
	 return STS_FAILURE;
      }
      DEBUGC(DBCLASS_NET,"allocated send socket %i",*sock);
   }

   if (buffer == NULL) {
      ERROR("sipsock_send_udp go tNULL buffer");
      return STS_FAILURE;
   }

   dst_addr.sin_family = AF_INET;
   memcpy(&dst_addr.sin_addr.s_addr, &addr, sizeof(struct in_addr));
   dst_addr.sin_port= htons(port);

   if (allowdump) {
      DEBUGC(DBCLASS_NET,"send UDP packet to %s: %i",
             inet_ntoa(addr),port);
      DUMP_BUFFER(DBCLASS_NETTRAF, buffer, size);
   }

   sts = sendto(*sock, buffer, size, 0, (const struct sockaddr *)&dst_addr,
                (socklen_t)sizeof(dst_addr));
   
   if (sts == -1) {
      if (errno != ECONNREFUSED) {
         ERROR("sendto() call failed: %s",strerror(errno));
         return STS_FAILURE;
      }
     DEBUGC(DBCLASS_BABBLE,"sendto() call failed:%s",strerror(errno));
   }

   return STS_SUCCESS;
}



/*
 * generic routine to allocate and bind a socket to a specified
 * local address and port (UDP)
 *
 * RETURNS socket number on success, zero on failure
 */
int sockbind(struct in_addr ipaddr, int localport) {
   struct sockaddr_in my_addr;
   int sts;
   int sock;

   my_addr.sin_family = AF_INET;
   memcpy(&my_addr.sin_addr.s_addr, &ipaddr, sizeof(struct in_addr));
   my_addr.sin_port= htons(localport);

   sock=socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if (sock == 0) {
      ERROR("socket() call failed:%s",strerror(errno));
      return 0;
   }

   sts=bind(sock, (struct sockaddr *)&my_addr, sizeof(my_addr));
   if (sts != 0) {
      ERROR("bind failed:%s",strerror(errno));
      close(sock);
      return 0;
   }

   return sock;
}

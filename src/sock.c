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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <osip/smsg.h>

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";

/* configuration storage */
extern struct siproxd_config configuration;

extern int errno;

static int listen_socket=0;

/*
 * binds to SIP UDP socket for listening to incomming packets
 *
 * returns 0 on success
 */
int sipsock_listen (void) {
   struct sockaddr_in my_addr;
   int sts;

   my_addr.sin_family = AF_INET;
   memset(&my_addr.sin_addr.s_addr, 0, sizeof(struct in_addr));
   my_addr.sin_port= htons(configuration.sip_listen_port);

   listen_socket=socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if (listen_socket == 0) {
      ERROR("socket() call failed:%s",strerror(errno));
      return 1;
   }

   sts=bind(listen_socket, (struct sockaddr *)&my_addr, sizeof(my_addr));
   if (sts != 0) {
      ERROR("bind failed:%s",strerror(errno));
      return 2;
   }

   DEBUGC(DBCLASS_NET,"bound listen socket %i",listen_socket);
   return 0;
}


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

int sipsock_read(void *buf, size_t bufsize) {
   int count;
   count=read(listen_socket, buf, bufsize);

   DEBUGC(DBCLASS_NET,"received UDP packet, count=%i", count);
   DUMP_BUFFER(DBCLASS_NETTRAF, buf, count);

   return count;
}


/*
 * sends an UDP datagram to the specified destination
 */
int sipsock_send_udp(struct in_addr addr, int port, char *buffer, int size) {
   struct sockaddr_in dst_addr;
   static int s=0;
   int sts;

   /* first time: allocate a socket for sending */
   if (s == 0) {
      s=socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if (s == 0) {
         ERROR("socket() call failed:%s",strerror(errno));
	 return 1;
      }
      DEBUGC(DBCLASS_NET,"allocated send socket %i",s);
   }

   dst_addr.sin_family = AF_INET;
   memcpy(&dst_addr.sin_addr.s_addr, &addr, sizeof(struct in_addr));
   dst_addr.sin_port= htons(port);

   DEBUGC(DBCLASS_NET,"send UDP packet to %s",inet_ntoa(addr));
   DUMP_BUFFER(DBCLASS_NETTRAF, buffer, size);

   sts = sendto (s, buffer, size, 0, &dst_addr, sizeof(dst_addr));
   
   if (sts == -1) {
      ERROR("sendto() call failed:%s",strerror(errno));
      return 1;
   }

   return 0;
}


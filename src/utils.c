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

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <osip/smsg.h>
#include <osip/port.h>

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";

/* configuration storage */
extern struct siproxd_config configuration;

extern int h_errno;

sip_t *msg_make_template_reply (sip_t * request, int code) {
   sip_t *response;
   char *tmp;
   int pos;

   msg_init (&response);
   msg_setversion (response, sgetcopy ("SIP/2.0"));
   tmp = malloc(5);
   snprintf (tmp, 5, "%i", code);
   msg_setstatuscode (response, tmp);
   msg_setreasonphrase (response, msg_getreason (code));

   to_clone (request->to, &response->to);
   from_clone (request->from, &response->from);


   /* via headers */
   pos = 0;
   while (!list_eol (request->vias, pos)) {
      via_t *via;
      via = (via_t *) list_get (request->vias, pos);
      via_2char (via, &tmp);

      msg_setvia (response, tmp);
      free (tmp);
      pos++;
   }

   call_id_clone(request->call_id,&response->call_id);
   cseq_clone(request->cseq,&response->cseq);

   return response;
}


int check_vialoop (sip_t *my_msg) {
   int sts;
   int pos;
   int found_own_via;

   found_own_via=0;
   pos = 1;	/* for detecting a loop, don't check the first entry 
   		   as this is my VIA! */
   while (!list_eol (my_msg->vias, pos)) {
      via_t *via;
      via = (via_t *) list_get (my_msg->vias, pos);
      sts = is_via_local (via);
      if (sts == 1) found_own_via=1;
      pos++;
   }
   return found_own_via;
}


int is_via_local (via_t *via) {
   int sts;
   struct in_addr addr_via, addr_myself;
   char *my_hostnames[]=
        { configuration.inboundhost, configuration.outboundhost, NULL };
   int i;
   char *ptr;

   DEBUGC(DBCLASS_BABBLE,"via name %s",via->host);
   if (inet_aton(via->host,&addr_via) == 0) {
      /* need name resolution */
      get_ip_by_host(via->host, &addr_via);
   }   

/* make this more optimized!!
do the lookup at the beginning and then compare against all
the via entries !
*/
   sts=0;
   for (i=0; ; i++) {
      ptr=my_hostnames[i];
      if (ptr==NULL) break;

      DEBUGC(DBCLASS_BABBLE,"local name %s",ptr);
      /* check the extracted VIA against my own host addresses */
      sts = get_ip_by_host(ptr, &addr_myself);

      if (memcmp(&addr_myself, &addr_via, sizeof(addr_myself))==0) {
         sts=1;
	 break;
      }
   }

   return sts; 
}

int get_ip_by_host(char *hostname, struct in_addr *addr) {
   struct hostent *hostentry;
/* &&&& bahh, figure out a way to make this stuff non-blocking*/
/* an asynchronous name-resolving might be neat */

   hostentry=gethostbyname(hostname);

   if (hostentry==NULL) {
      ERROR("gethostbyname(%s) failed: %s",hostname,hstrerror(h_errno));
      return 1;
   }

   memcpy(addr, hostentry->h_addr, sizeof(struct in_addr));
   DEBUGC(DBCLASS_BABBLE, "resolved: %s -> %s", hostname, inet_ntoa(*addr));

   return 0;
}



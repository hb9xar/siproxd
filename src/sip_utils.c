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
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <sys/types.h>
#include <pwd.h>

#ifdef HAVE_OSIP2
   #include <osip2/smsg.h>
   #include <osip2/port.h>
#else
   #include <osip/smsg.h>
   #include <osip/port.h>
#endif

#include "siproxd.h"
#include "rewrite_rules.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";

/* configuration storage */
extern struct siproxd_config configuration;

extern int h_errno;


/*
 * create a reply template from an given SIP request
 *
 * RETURNS a pointer to sip_t
 */
sip_t *msg_make_template_reply (sip_t * request, int code) {
   sip_t *response;
   char *tmp;
   int pos;

   msg_init (&response);
   msg_setversion (response, sgetcopy ("SIP/2.0"));
   tmp = malloc(STATUSCODE_SIZE);
   snprintf (tmp, STATUSCODE_SIZE, "%i", code);
   msg_setstatuscode (response, tmp);
   msg_setreasonphrase (response, msg_getreason (code));

   if (request->to==NULL) {
      ERROR("msg_make_template_reply: empty To in request header");
   }

   if (request->from==NULL) {
      ERROR("msg_make_template_reply: empty From in request header");
   }

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


/*
 * check for a via loop.
 * It checks for the presense of a via entry that holds one of
 * my IP addresses and is *not* the topmost via.
 *
 * RETURNS
 *	STS_TRUE if loop detected
 *	STS_FALSE if no loop
 */
int check_vialoop (sip_t *my_msg) {
/*
!!! actually this is a problematic one.
1) for requests, I must search the whole VIA list
   (topmost via is the previos station in the path)

2) for responses I must skip the topmost via, as this is mine
   (and will be removed later on)

3) What happens if we have 'clashes'  with private addresses??
   From that point of view, siproxd *should* not try to
   check against it's local IF addresses if thei are private.
   this then of course again can lead to a endless loop...
   
   can we use something like a Tag in via headers?? (a veriy likely
   to-be-unique ID)

*/
   int sts;
   int pos;
   int found_own_via;

   found_own_via=0;
   pos = 1;	/* for detecting a loop, don't check the first entry 
   		   as this is my own VIA! */
   while (!list_eol (my_msg->vias, pos)) {
      via_t *via;
      via = (via_t *) list_get (my_msg->vias, pos);
      sts = is_via_local (via);
      if (sts == STS_TRUE) found_own_via=1;
      pos++;
   }
   return (found_own_via)? STS_TRUE : STS_FALSE;
}


/*
 * check if a given via_t is local. I.e. its address is owned
 * by my inbound or outbound interface
 *
 * RETURNS
 *	STS_TRUE if the given VIA is one of my interfaces
 *	STS_FALSE otherwise
 */
int is_via_local (via_t *via) {
   int sts, found;
   struct in_addr addr_via, addr_myself;
   char *my_interfaces[]=
        { configuration.inbound_if,  configuration.outbound_if,  (char*)-1 };
   int port;
   int i;
   char *ptr;

   if (via==NULL) {
      ERROR("called is_via_local with NULL via");
      return STS_FALSE;
   }

   DEBUGC(DBCLASS_BABBLE,"via name %s",via->host);
   if (inet_aton(via->host,&addr_via) == 0) {
      /* need name resolution */
      get_ip_by_host(via->host, &addr_via);
   }   

   found=0;
   for (i=0; ; i++) {
      /*
       * try to search by interface name first
       */
      ptr=my_interfaces[i];
      if (ptr==(char*)-1) break; /* end of list mark */

      if (ptr) {
         DEBUGC(DBCLASS_BABBLE,"resolving IP of interface %s",ptr);
         sts = get_ip_by_ifname(ptr, &addr_myself);
      }

      /* check the extracted VIA against my own host addresses */
      if (via->port) port=atoi(via->port);
      else port=SIP_PORT;

      if ( (memcmp(&addr_myself, &addr_via, sizeof(addr_myself))==0) &&
           (port == configuration.sip_listen_port) ) {
         DEBUG("address match [%s] <-> [%s]", inet_ntoa(addr_myself),
               inet_ntoa(addr_via));
         found=1;
	 break;
      }
   }

   return (found)? STS_TRUE : STS_FALSE;
}


/*
 * compares two URLs
 * (by now, only hostname and username are compared)
 *
 * RETURNS
 *	STS_SUCCESS if equal
 *	STS_FAILURE if non equal or error
 */
int compare_url(url_t *url1, url_t *url2) {
   int sts;
   struct in_addr addr1, addr2;

   /* sanity checks */
   if ((url1 == NULL) || (url2 == NULL)) {
      ERROR("compare_url: NULL ptr: url1=0x%p, url2=0x%p",url1, url2);
      return STS_FAILURE;
   }

   /* sanity checks: host part is a MUST */
   if ((url1->host == NULL) || (url2->host == NULL)) {
      ERROR("compare_url: NULL ptr: url1->host=0x%p, url2->host=0x%p",
            url1->host, url2->host);
      return STS_FAILURE;
   }

   /* get the IP addresses from the (possible) hostnames */
   get_ip_by_host(url1->host, &addr1);
   get_ip_by_host(url2->host, &addr2);

   /* Broken(?) MSN messenger - does not supply a user name part.
      So we simply compare the host part then */
   if ((url1->username == NULL) || (url2->username == NULL)) {
      WARN("compare_url: NULL username pointer: MSN messenger is known to "
           "trigger this one!");
      DEBUGC(DBCLASS_DNS, "comparing broken urls (no user): "
            "%s[%s] -> %s[%s]",
            url1->host, inet_ntoa(addr1), url2->host, inet_ntoa(addr2));
      if (memcmp(&addr1, &addr2, sizeof(addr1))==0) {
         sts = STS_SUCCESS;
      } else {
         sts = STS_FAILURE;
      }
      return sts;
   }

   /* we have a proper URL */
   /* comparison of hosts should be based on IP addresses, no? */
   DEBUGC(DBCLASS_DNS, "comparing urls: %s@%s[%s] -> %s@%s[%s]",
         url1->username, url1->host, inet_ntoa(addr1),
         url2->username, url2->host, inet_ntoa(addr2));
   if ((strcmp(url1->username, url2->username)==0) &&
       (memcmp(&addr1, &addr2, sizeof(addr1))==0)) {
      sts = STS_SUCCESS;
   } else {
      sts = STS_FAILURE;
   }

   return sts;
}


/*
 * check if a given request is addressed to local. I.e. it is addressed
 * to the porxy itself (IP of my inbound or outbound interface, same port)
 *
 * RETURNS
 *	STS_TRUE if the request is addressed local
 *	STS_FALSE otherwise
 */
int is_sipuri_local (sip_t *sip) {
   int sts, found;
   struct in_addr addr_uri, addr_myself;
   char *my_interfaces[]=
        { configuration.inbound_if,  configuration.outbound_if,  (char*)-1 };
   int port;
   int i;
   char *ptr;

   if (sip==NULL) {
      ERROR("called is_sipuri_local with NULL sip");
      return STS_FALSE;
   }

   if (!sip || !sip->strtline || !sip->strtline->rquri) {
      ERROR("is_sipuri_local: no request URI present");
      return STS_FALSE;
   }

   DEBUGC(DBCLASS_DNS,"check for local SIP URI %s:%s",
          sip->strtline->rquri->host? sip->strtline->rquri->host : "*NULL*",
          sip->strtline->rquri->port? sip->strtline->rquri->port : "*NULL*");

   if (inet_aton(sip->strtline->rquri->host, &addr_uri) == 0) {
      /* need name resolution */
      get_ip_by_host(sip->strtline->rquri->host, &addr_uri);
   }   

   found=0;
   for (i=0; ; i++) {
      /*
       * try to search by interface name first
       */
      ptr=my_interfaces[i];
      if (ptr==(char*)-1) break; /* end of list mark */

      if (ptr) {
         DEBUGC(DBCLASS_BABBLE,"resolving IP of interface %s",ptr);
         sts = get_ip_by_ifname(ptr, &addr_myself);
      }

      /* check the extracted HOST against my own host addresses */
      if (sip->strtline->rquri->port) {
         port=atoi(sip->strtline->rquri->port);
      } else {
         port=SIP_PORT;
      }

      if ( (memcmp(&addr_myself, &addr_uri, sizeof(addr_myself))==0) &&
           (port == configuration.sip_listen_port) ) {
         DEBUG("address match [%s] <-> [%s]", inet_ntoa(addr_myself),
               inet_ntoa(addr_uri));
         found=1;
	 break;
      }
   }

   DEBUGC(DBCLASS_DNS, "SIP URI is %slocal", found? "":"not ");
   return (found)? STS_TRUE : STS_FALSE;
}


/*
 * check if a given request (outbound -> inbound) shall its
 * request URI get rewritten based upon our UA knowledge
 *
 * RETURNS
 *	STS_TRUE if to be rewritten
 *	STS_FALSE otherwise
 */
int check_rewrite_rq_uri (sip_t *sip) {
   int i, j, sts;
   int dflidx;
   header_t *ua_hdr;

   /* get index of default entry */
   dflidx=(sizeof(RQ_rewrite)/sizeof(RQ_rewrite[0])) - 1;

   /* check fort existence of method */
   if ((sip==NULL) || (sip->strtline==NULL) || 
       (sip->strtline->sipmethod==NULL)) {
      ERROR("check_rewrite_rq_uri: got NULL method");
      return STS_FALSE;
   }

   /* extract UA string */
   msg_getuser_agent (sip, 0, &ua_hdr);
   if ((ua_hdr==NULL) || (ua_hdr->hvalue==NULL)) {
      WARN("check_rewrite_rq_uri: NULL UA in Header, using default");
      i=dflidx;
   } else {
      /* loop through the knowledge base */
      for (i=0; RQ_rewrite[i].UAstring; i++) {
         if (strncmp(RQ_rewrite[i].UAstring, ua_hdr->hvalue,
                    sizeof(RQ_rewrite[i].UAstring))==0) {
            DEBUGC(DBCLASS_SIP, "got knowledge entry for [%s]",
                   ua_hdr->hvalue);
            break;
         }
      } /* for i */
   } /* if ua_hdr */

   for (j=0; RQ_method[j].name; j++) {
      if (strncmp(RQ_method[j].name,
                 sip->strtline->sipmethod, RQ_method[j].size)==0) {
         if (RQ_rewrite[i].action[j] >= 0) {
            sts = (RQ_rewrite[i].action[j])? STS_TRUE: STS_FALSE;
         } else {
	    sts = (RQ_rewrite[dflidx].action[j])? STS_TRUE: STS_FALSE;
         }
         DEBUGC(DBCLASS_SIP, "check_rewrite_rq_uri: [%s:%s, i=%i, j=%i] "
                "got action %s",
                (sip && sip->strtline && sip->strtline->sipmethod) ?
                  sip->strtline->sipmethod : "*NULL*",
                (ua_hdr && ua_hdr->hvalue)? ua_hdr->hvalue:"*NULL*",
                 i, j, (sts==STS_TRUE)? "rewrite":"norewrite");
         return sts;
      }
   } /* for j */

   WARN("check_rewrite_rq_uri: didn't get a hit of the method [%s]",
        sip->strtline->sipmethod);
   return STS_FALSE;
}



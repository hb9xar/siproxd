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
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osip/smsg.h>

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";

/* configuration storage */
extern struct siproxd_config configuration;

struct urlmap_s urlmap[URLMAP_SIZE];		/* URL mapping table     */
extern int sip_socket;				/* sending SIP datagrams */

/*
 * initialize the URL mapping table
 */
void register_init(void) {
   memset (urlmap, 0, sizeof(urlmap));
   return;
}


/*
 * handles register requests and updates the URL mapping table
 *
 * RETURNS:
 *    STS_SUCCESS : successfully registered
 *    STS_FAILURE : registration failed
 *    STS_NEED_AUTH : authentication needed
 */
int register_client(sip_t *my_msg) {
   int i, j, sts;
   int expires;
   time_t time_now;
   url_t *url1_to, *url1_contact;
   url_t *url2_to, *url2_contact;
   header_t *expires_hdr;
   
   /* check for proxy authentication */
   sts = authenticate_proxy(my_msg);
   if (sts == STS_FAILURE) {
   /* failed */
      WARN("proxy authentication failed for %s@%s",
           my_msg->to->url->username,my_msg->to->url->host);
      return STS_FAILURE;
   } else if (sts == STS_NEED_AUTH) {
      /* needed */
      DEBUGC(DBCLASS_REG,"proxy authentication needed for %s@%s",
             my_msg->to->url->username,my_msg->to->url->host);
      return STS_NEED_AUTH;
   }

/*
   fetch 1st Via entry and remember this address. Incomming requests
   for the registered address have to be passed on to that host.

   To: -> address to be registered
   Contact: -> host is reachable there
   
   => Mapping is
   To: <1--n> Contact
   
*/
   time(&time_now);

   DEBUGC(DBCLASS_BABBLE,"sip_register:");

   /* evaluate Expires Header field */
   msg_getexpires(my_msg, 0, &expires_hdr);

   if (expires_hdr) {
      expires=atoi(expires_hdr->hvalue);
   } else {
      /* it seems the expires filed in not present everywhere... */
      WARN("no 'expires' header found - set time to 600 sec");
      expires=600;
      msg_setexpires(my_msg, "600");
   }
   DEBUGC(DBCLASS_REG,"expires:%i seconds",expires);


/* Update registration. There are two possibilities:
 * - already registered, the update the existing record
 * - not registered, then create a new record
 */
   url1_to=my_msg->to->url;
   url1_contact=((contact_t*)(my_msg->contacts->node->element))->url;

   j=-1;
   for (i=0; i<URLMAP_SIZE; i++) {
      if (urlmap[i].active == 0) {
	 if (j < 0) j=i; /* remember first hole */
         continue;
      }

      url2_to=urlmap[i].masq_url;
      url2_contact=urlmap[i].true_url;

      if ( (compare_url(url1_to, url2_to)==STS_SUCCESS) &&
           (strcmp(url1_contact->username, url2_contact->username)==0) &&
           (strcmp(url1_contact->host,     url2_contact->host    )==0) ) {
         DEBUGC(DBCLASS_REG, "found entry for %s@%s at slot=%i, exp=%li",
	        url1_contact->username,url1_contact->host,
		i, urlmap[i].expires-time_now);
         break;
      }
   }

   if ( (j < 0) && (i >= URLMAP_SIZE) ) {
      /* oops, no free entries left... */
      ERROR("URLMAP is full - registration failed");
      return STS_FAILURE;
   }

   if (i >= URLMAP_SIZE) {
      /* entry not existing, create new one */
      i=j;
      DEBUGC(DBCLASS_REG,"create new entry for %s@%s at slot=%i",
             url1_contact->username, url1_contact->host, i);

      /* write entry */
      urlmap[i].active=1;
      url_clone( ((contact_t*)(my_msg->contacts->node->element))->url, 
        	 &urlmap[i].true_url);	/* Contact: field */
      url_clone( my_msg->to->url, 
        	 &urlmap[i].masq_url);	/* To: field */
      via_clone( ((via_t*)(my_msg->vias->node->element)),
                 &urlmap[i].via);	/* via field */
   }

   /* give some safety margin for the next update */
   if (expires >0) expires+=30;

   /* update registration timeout */
   urlmap[i].expires=time_now+expires;

   return STS_SUCCESS;
}



/*
 * cyclically called to do the aging of the URL mapping table entries
 * and throw out expired entries.
 */
void register_agemap(void) {
   int i;
   time_t t;
   
   time(&t);
   DEBUGC(DBCLASS_BABBLE,"sip_agemap, t=%i",(int)t);
   for (i=0; i<URLMAP_SIZE; i++) {
      if ((urlmap[i].active == 1) && (urlmap[i].expires < t)) {
	 DEBUGC(DBCLASS_REG,"cleaned entry:%i %s@%s", i,
	        urlmap[i].masq_url->username,  urlmap[i].masq_url->host);
         urlmap[i].active=0;
         url_free(urlmap[i].true_url);
         url_free(urlmap[i].masq_url);
	 via_free(urlmap[i].via);
         free(urlmap[i].true_url);
	 free(urlmap[i].masq_url);
	 free(urlmap[i].via);
      }
   }
   return;
}


/*
 * send answer to a registration request.
 *  flag = STS_SUCCESS    -> positive answer (200)
 *  flag = STS_FAILURE    -> negative answer (503)
 *  flag = STS_NEED_AUTH  -> proxy authentication needed (407)
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int register_response(sip_t *request, int flag) {
   sip_t *response;
   int code;
   int sts;
   via_t *via;
   int port;
   char *buffer;
   struct in_addr addr;
   header_t *expires_hdr;

   /* ok -> 200, fail -> 503 */
   switch (flag) {
   case STS_SUCCESS:
      code = 200;	/* OK */
      break;
   case STS_FAILURE:
      code = 503;	/* failed */
      break;
   case STS_NEED_AUTH:
      code = 407;	/* proxy authentication needed */
      break;
   default:
      code = 503;	/* failed */
      break;
   }

   /* create the response template */
   if ((response=msg_make_template_reply(request, code))==NULL) {
      ERROR("register_response: error in msg_make_template_reply");
      return STS_FAILURE;
   }

   /* insert the expiration header */
   msg_getexpires(request, 0, &expires_hdr);
   if (expires_hdr) {
      msg_setexpires(response, expires_hdr->hvalue);
   }

   /* if we send back an proxy authentication needed, 
      include the Proxy-Authenticate field */
   if (code == 407) {
      auth_include_authrq(response);
   }

   /* get the IP address from existing VIA header */
   msg_getvia (response, 0, &via);
   if (via == NULL) {
      ERROR("register_response: Cannot send response - no via field");
      return STS_FAILURE;
   }

   /* name resolution needed? */
   if (inet_aton (via->host,&addr) == 0) {
      /* yes, get IP address */
      sts = get_ip_by_host(via->host, &addr);
   }   

   sts = msg_2char(response, &buffer);
   if (sts != 0) {
      ERROR("register_response: msg_2char failed");
      return STS_FAILURE;
   }

   /* send answer back */
   if (via->port) {
      port=atoi(via->port);
   } else {
      port=configuration.sip_listen_port;
   }

   sipsock_send_udp(&sip_socket, addr, port, buffer, strlen(buffer), 1);

   /* free the resources */
   msg_free(response);
   free(response);
   free(buffer);
   return STS_SUCCESS;
}


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
#include <netdb.h>

#include <osip/smsg.h>

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";


/* configuration storage */
extern struct siproxd_config configuration;

/*
 * knows hot to rewrite the SIP URLs in a request/response
 */

extern int errno;
extern struct urlmap_s urlmap[];		// URL mapping table
extern struct lcl_if_s local_addresses;

int proxy_request (sip_t *request) {
   int i;
   int sts;
   int type;
   struct in_addr addr;
   contact_t *contact;
   url_t *url;
   int port;
   char *buffer;

#define REQTYP_INCOMMING	1
#define REQTYP_OUTGOING		2

   DEBUGC(DBCLASS_PROXY,"proxy_request");

/* check for VIA loop, if yes, discard the request */
   sts=check_vialoop(request);
   if (sts !=0) {
      DEBUGC(DBCLASS_PROXY,"via loop detected, ignoring request");
      return 1;
   }

   /* figure out if this is an request comming from the outside
    * world to one of our registered clients ('to' == 'masq' URL)
    * or if this is a request sent by on e of our registered clients
    * ('from' == 'true' URL) 
    */
   msg_getcontact(request,0,&contact);
   type = 0;
   for (i=0; i<URLMAP_SIZE; i++) {
      if (urlmap[i].active == 0) continue;

      /* incomming request ('to' == 'masq') */
      if (compare_url(request->to->url, urlmap[i].masq_url)==0) {
         type=REQTYP_INCOMMING;
         DEBUGC(DBCLASS_PROXY,"incomming request from %s@%s from outbound",
	        request->from->url->username,
		request->from->url->host);
	 break;
      }

      /* outgoing request ('contact' == 'true') */
      if (compare_url(contact->url, urlmap[i].true_url)==0) {
         type=REQTYP_OUTGOING;
         DEBUGC(DBCLASS_PROXY,"outgoing request from %s@%s from inbound",
	        request->from->url->username,
		request->from->url->host);
	 break;
      }
   }


/*
 * ok, we got a request that we are allowed to process.
 */
   switch (type) {
  /*
   * from an external host to the internal masqueraded host
   */
   case REQTYP_INCOMMING:
      /* rewrite request URI to point to the real host */
      /* i still holds the valid index into the URLMAP table */

      /* THIS IS UGLY!!! I dont like it */
      DEBUGC(DBCLASS_PROXY,"rewriting incomming Request URI");
      url=msg_geturi(request);
      free(url->host);url->host=NULL;
{
      char *copy;
      copy = (char *)malloc(strlen(urlmap[i].true_url->host)+1);
      memcpy(copy, urlmap[i].true_url->host, strlen(urlmap[i].true_url->host));
      copy[strlen(urlmap[i].true_url->host)]='\0';
      url_sethost(url, copy);
}

      /* add my Via header line (inbound interface)*/
      sts = proxy_add_myvia(request, 1);
      break;
   
  /*
   * from the internal masqueraded host to an external host
   */
   case REQTYP_OUTGOING:
      /* if an INVITE, rewrite body */
      if (MSG_IS_INVITE(request)) {
         sts = proxy_rewrite_invitation_body(request);
      }

      /* add my Via header line (outbound interface)*/
      sts = proxy_add_myvia(request, 0);
      break;
   
   default:
      DEBUGC(DBCLASS_PROXY,"request: refuse to proxy - UA not registered?");
/* some clients seem to run amok when passing back a negative response */
//      proxy_gen_response(request, 403 /*forbidden*/);
      return 1;
   }


/* get target address from request URL */
   url=msg_geturi(request);

#ifdef HACK1
/* linphone-0.9.0pre4
   take To address and place it into URI (at least the host part)
   Linphone-0.9.0pre4 puts the proxy host in the request URI
   if OUTBOUNT proxy is activated!
   This is only a hack to recreate the proper final request URI.
   This issue has been fixed in 0.9.1pre1
*/
{
   header_t *header_ua;
   msg_getuser_agent(request,0,&header_ua);

   if ( header_ua && header_ua->hvalue &&
        (strcmp(header_ua->hvalue,"oSIP/Linphone-0.8.0")==0) ) {
      /* if an outgoing request, try to fix the SIP URI */
      if (type == REQTYP_OUTGOING) {
         WARN("broken linphone-0.8.0: restoring SIP URI");
	 free (url->host);
	 url->host=malloc(strlen(request->to->url->host));
	 strcpy(url->host,request->to->url->host);

      }
   }
}
#endif

   sts = get_ip_by_host(url->host, &addr);

   sts = msg_2char(request, &buffer);
   if (sts != 0) {
      ERROR("proxy_request: msg_2char failed");
      return 1;
   }

   /* send to destination */
   if (url->port) {
      port=atoi(url->port);
   } else {
      port=configuration.sip_listen_port;
   }

   sipsock_send_udp(addr, port, buffer, strlen(buffer)); 
   free (buffer);
   return 0;
}


int proxy_response (sip_t *response) {
   int i;
   int sts;
   int type;
   struct in_addr addr;
   via_t *via;
   int port;
   char *buffer;

#define RESTYP_INCOMMING	1
#define RESTYP_OUTGOING		2

   DEBUGC(DBCLASS_PROXY,"proxy_response");


   /* check for VIA loop, if yes, discard the request */
   sts=check_vialoop(response);
   if (sts !=0) {
      DEBUGC(DBCLASS_PROXY,"via loop detected, ignoring response");
      return 1;
   }

   /* ALWAYS: remove my Via header line */
   sts = proxy_del_myvia(response);
   if (sts !=0) {
      DEBUGC(DBCLASS_PROXY,"not addressed to my VIA, ignoring response");
      return 1;
   }

   /* figure out if this is an request comming from the outside
    * world to one of our registered clients
    */


   /* Ahhrghh...... an response seems to have NO contact information... 
    * so let's take FROM instead...
    * the TO and FROM headers are EQUAL to the request - that means 
    * they are swapped in their meaning for a response...
    */

   type = 0;
   for (i=0; i<URLMAP_SIZE; i++) {
      if (urlmap[i].active == 0) continue;


      /* incomming response ('from' == 'masq') */
      if (compare_url(response->from->url, urlmap[i].masq_url)==0) {
         type=RESTYP_INCOMMING;
         DEBUGC(DBCLASS_PROXY,"incomming response for %s@%s from outbound",
	        response->from->url->username,
		response->from->url->host);
	 break;
      }

      /* outgoing response ('to' == 'masq') */
      if (compare_url(response->to->url, urlmap[i].masq_url)==0) {
         type=RESTYP_OUTGOING;
         DEBUGC(DBCLASS_PROXY,"outgoing response for %s@%s from inbound",
	        response->from->url->username,
		response->from->url->host);
	 break;
      }
   }

/*
 * ok, we got a response that we are allowed to process.
 */
   switch (type) {
  /*
   * from an external host to the internal masqueraded host
   */
   case RESTYP_INCOMMING:
#if 0 /* do we really have to?? in the incomming response
         we have the correct address. But we mus rewrite an
	 outgoing response to an incomming INVITE request ! */
      /* If an 200 answer to an INVITE request, rewrite body */
      if ((MSG_IS_RESPONSEFOR(response,"INVITE") &&
          (MSG_TEST_CODE(response, 200)) ) {
         sts = proxy_rewrite_invitation_body(response);
      }
#endif

      break;
   
  /*
   * from the internal masqueraded host to an external host
   */
   case RESTYP_OUTGOING:
      #define satoi atoi  /* used in MSG_TEST_CODE macro ... */
      /* If an 200 answer to an INVITE request, rewrite body */
      if ((MSG_IS_RESPONSEFOR(response,"INVITE")) &&
          (MSG_TEST_CODE(response, 200))) {
         sts = proxy_rewrite_invitation_body(response);
      }
      break;
   
   default:
      DEBUGC(DBCLASS_PROXY,"response: refuse to proxy - UA not registered?");
/* some clients seem to run amok when passing back a negative response */
//      proxy_gen_response(request, 403 /*forbidden*/);
      return 1;
   }

   /* get target address from VIA header */
   via = (via_t *) list_get (response->vias, 0);

   sts = get_ip_by_host(via->host, &addr);

   sts = msg_2char(response, &buffer);
   if (sts != 0) {
      ERROR("proxy_request: msg_2char failed");
      return 1;
   }

   /* send to destination */
   if (via->port) {
      port=atoi(via->port);
   } else {
      port=configuration.sip_listen_port;
   }

   sipsock_send_udp(addr, port, buffer, strlen(buffer)); 
   free (buffer);
   return 0;
}







/*
 * send an proxy generated response back to the client.
 * Only errors are reported from the proxy itself.
 *  code =  SIP result code to deliver
 */
int proxy_gen_response(sip_t *request, int code) {
   sip_t *response;
   int sts;
   via_t *via;
   char *buffer;
   struct in_addr addr;

   /* create the response template */
   if ((response=msg_make_template_reply(request, code))==NULL) {
      ERROR("proxy_response: error in msg_make_template_reply");
      return 1;
   }

   /* we must check if first via has x.x.x.x address. If not, we must resolve it */
   msg_getvia (response, 0, &via);
   if (via == NULL)
   {
      ERROR("proxy_response: Cannot send response - no via field");
      return 1;
   }


/* name resolution */
   if (inet_aton (via->host,&addr) == 0)
   {
      /* need name resolution */
      DEBUGC(DBCLASS_DNS,"resolving name:%s",via->host);
      sts = get_ip_by_host(via->host, &addr);
   }   

DEBUGC(DBCLASS_PROXY,"response=%p",response);
   sts = msg_2char(response, &buffer);
   if (sts != 0) {
      ERROR("proxy_response: msg_2char failed");
      return 1;
   }

   /* send to destination */
   sipsock_send_udp(addr, atoi(via->port), buffer, strlen(buffer));

   /* free the resources */
   msg_free(response);
   free(response);
   free (buffer);
   return 0;
}


/*
 * routine to rewrite the header and message bodies
 */

/* interface == 0 -> outbound interface, else inbound interface */
int proxy_add_myvia (sip_t *request, int interface) {
   struct in_addr addr;
   char tmp[URL_STRING_SIZE];
   via_t *via;
   int sts;

   if (interface == 0) {
      sts = get_ip_by_host(configuration.outboundhost, &addr);
   } else {
      sts = get_ip_by_host(configuration.inboundhost, &addr);
   }

   sprintf (tmp, "SIP/2.0/UDP %s:%i", inet_ntoa(addr),
            configuration.sip_listen_port);
   DEBUGC(DBCLASS_BABBLE,"adding VIA:%s",tmp);

   sts = via_init(&via);
   if (sts!=0) return -1; /* allocation failed */
   sts = via_parse(via, tmp);
   if (sts!=0) return -1;
   list_add(request->vias,via,0);

   return 0;
}



int proxy_del_myvia (sip_t *response) {
   via_t *via;
   int sts;

   DEBUGC(DBCLASS_PROXY,"deleting topmost VIA");
   via = list_get (response->vias, 0);
   
   if ( !is_via_local(via) ) {
      ERROR("I'm trying to delete a VIA but it's not mine! host=%s",via->host);
      return -1;
   }

   sts = list_remove(response->vias, 0);
   via_free (via);
   free(via);
   return 0;
}



int proxy_rewrite_invitation_body(sip_t *mymsg){
   body_t *body;
   struct in_addr addr;
   int sts;
   char *oldbody;
   char newbody[BODY_MESSAGE_MAX_SIZE];
   char clen[8]; /* probably never more than 7 digits for content length !*/

   sts = msg_getbody(mymsg, 0, &body);
   if (sts != 0) {
      ERROR("rewrite_invitation_body: no body found in message");
      return 1;
   }

   sts = body_2char(body, &oldbody);

{
   char *tmp2;
   content_length_2char(mymsg->contentlength, &tmp2);
   DEBUG("Body before rewrite (clen=%s, strlen=%i):\n%s\n----",
         tmp2, strlen(oldbody), oldbody);
   free(tmp2);
}


/* TODO */
/* - change the 'c=' line to present the outbound address (the other
     side will send its audio data there 
   - 'm=' line: here we should change the port number to a free local
     (outbound) port and set up an port forwarding to the hidden
     inbound client ...*/


{
   char *data=NULL;
   char *data2=NULL;
   char *ptr=NULL;

   memset(newbody, 0, sizeof(newbody));

   data = strstr (oldbody, "\nc=");
   if (data == NULL) data = strstr (oldbody, "\rc=");
   if (data == NULL) {
      ERROR("did not find a c= line in the body");
      return 1;
   }
   data += 3;

   /* can only rewrite IPV4 addresses by now */
   if (strncmp(data,"IN IP4 ",7)!=0) {
      ERROR("c= does not contain an IN IP4 address");
      return 1;
   }
   data += 7;

   data2 = strstr (data, "\n");
   if (data2 == NULL) data2 = strstr (oldbody, "\r");
   if (data2 == NULL) {
      ERROR("did not find a CR/LF after c= line");
      return 1;
   }

   /* copy up to the to-be-masqueraded address */
   memcpy(newbody, oldbody, data-oldbody);

   /* insert proxy outbound address */
   sts = get_ip_by_host(configuration.outboundhost, &addr);
   ptr=newbody+(data-oldbody);
   sprintf(ptr, "%s", inet_ntoa(addr));
   ptr += strlen(ptr);
   
   /* copy rest */
   memcpy (ptr, data2, strlen(data2));
}

   /* remove old body */
   sts = list_remove(mymsg->bodies, 0);
   body_free(body);
   free(body);

   /* include new body */
   msg_setbody(mymsg, newbody);

   /* free content length resource and include new one*/
   content_length_free(mymsg->contentlength);
   free(mymsg->contentlength);
   mymsg->contentlength=NULL;
   sprintf(clen,"%i",strlen(newbody));
   sts = msg_setcontent_length(mymsg, clen);


{
   char *tmp, *tmp2;
   sts = msg_getbody(mymsg, 0, &body);
   sts = body_2char(body, &tmp);
   content_length_2char(mymsg->contentlength, &tmp2);
   DEBUG("Body after rewrite (clen=%s, strlen=%i):\n%s\n----",
         tmp2, strlen(tmp), tmp);
   free(tmp);
   free(tmp2);
}
   free(oldbody);
   return 0;
}

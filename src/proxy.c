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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <osipparser2/osip_parser.h>
#include <osipparser2/sdp_message.h>

#include "siproxd.h"
#include "log.h"

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";


/* configuration storage */
extern struct siproxd_config configuration;

extern int errno;
extern struct urlmap_s urlmap[];		/* URL mapping table     */
extern struct lcl_if_s local_addresses;
extern int sip_socket;				/* sending SIP datagrams */


/*
 * PROXY_REQUEST
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_request (osip_message_t *request) {
   int i;
   int sts;
   int type;
   struct in_addr sendto_addr;
   osip_contact_t *contact;
   osip_uri_t *url;
   int port;
   char *buffer;

#define REQTYP_INCOMING		1
#define REQTYP_OUTGOING		2

   DEBUGC(DBCLASS_PROXY,"proxy_request");

/* check for VIA loop, if yes, discard the request */
   sts=check_vialoop(request);
   if (sts == STS_TRUE) {
      DEBUGC(DBCLASS_PROXY,"via loop detected, ignoring request");
      /* according to the SIP RFC we are supposed to return an 482 error */
      return STS_FAILURE;
   }

   type = 0;
   for (i=0; i<URLMAP_SIZE; i++) {
      if (urlmap[i].active == 0) continue;

      /* incoming request ('to' == 'masq') || (('to' == 'reg') && !REGISTER)*/
      if ((compare_url(request->to->url, urlmap[i].masq_url)==STS_SUCCESS) ||
          (!MSG_IS_REGISTER(request) &&
           (compare_url(request->to->url, urlmap[i].reg_url)==STS_SUCCESS))) {
         type=REQTYP_INCOMING;
         DEBUGC(DBCLASS_PROXY,"incoming request from %s@%s from outbound",
	   request->from->url->username? request->from->url->username:"*NULL*",
           request->from->url->host? request->from->url->host: "*NULL*");
	 break;
      }

      /* outgoing request ('from' == 'reg') */
      if (compare_url(request->from->url, urlmap[i].reg_url)==STS_SUCCESS) {
         type=REQTYP_OUTGOING;
         DEBUGC(DBCLASS_PROXY,"outgoing request from %s@%s from inbound",
	   request->from->url->username? request->from->url->username:"*NULL*",
           request->from->url->host? request->from->url->host: "*NULL*");
	 break;
      }
   }


/*
 * ok, we got a request that we are allowed to process.
 */
#ifdef HACK1
/* linphone-0.9.0pre4
   take To address and place it into URI (at least the host part)
   Linphone-0.9.0pre4 puts the proxy host in the request URI
   if OUTBOUND proxy is activated!
   This is only a hack to recreate the proper final request URI.
   This issue has been fixed in 0.9.1pre1
*/
{
   osip_header_t *header_ua;

   url=osip_message_get_uri(request);
   osip_message_get_user_agent(request,0,&header_ua);

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

   switch (type) {
  /*
   * from an external host to the internal masqueraded host
   */
   case REQTYP_INCOMING:
      sts = get_ip_by_host(urlmap[i].true_url->host, &sendto_addr);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: cannot resolve URI [%s]",
                url->host);
         return STS_FAILURE;
      }

      /* rewrite request URI to point to the real host */
      /* i still holds the valid index into the URLMAP table */
      if (check_rewrite_rq_uri(request)==STS_TRUE) {
         proxy_rewrite_request_uri(request, i);
      }

      /* add my Via header line (inbound interface)*/
      sts = sip_add_myvia(request, IF_INBOUND);
      if (sts == STS_FAILURE) {
         ERROR("adding my inbound via failed!");
         return STS_FAILURE;
      }

      /* if this is CANCEL/BYE request, stop RTP proxying */
      if (MSG_IS_BYE(request) || MSG_IS_CANCEL(request)) {
#ifdef MOREDEBUG /*&&&&*/
INFO("stopping RTP proxy stream for: %s@%s",
     osip_message_get_call_id(request)->number, 
     osip_message_get_call_id(request)->host);
#endif
         /* stop the RTP proxying stream */
         rtp_stop_fwd(osip_message_get_call_id(request));

      /* check for incomming request */
      } else if (MSG_IS_INVITE(request)) {
         osip_uri_t *contact;
         contact=((osip_contact_t*)(request->contacts->node->element))->url;
         if (contact) {
            INFO("Incomming Call from: %s:%s",
                 contact->username ? contact->username:"*NULL*",
                 contact->host ? contact->host : "*NULL*");
         } else {
            INFO("Incomming Call (w/o contact header) from: %s:%s",
	         request->from->url->username ? 
                    request->from->url->username:"*NULL*",
	         request->from->url->host ? 
                    request->from->url->host : "*NULL*");
         }
      }
      break;
   
  /*
   * from the internal masqueraded host to an external host
   */
   case  REQTYP_OUTGOING:
      /* get destination address */
      url=osip_message_get_uri(request);

      sts = get_ip_by_host(url->host, &sendto_addr);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: cannot resolve URI [%s]",
                url->host);
         return STS_FAILURE;
      }

      /* if it is addressed to myself, then it must be some request
       * method that I as a proxy do not support. Reject */
      if (is_sipuri_local(request) == STS_TRUE) {
         WARN("unsupported request [%s] directed to proxy from %s@%s -> %s@%s",
	    request->sip_method? request->sip_method:"*NULL*",
	    request->from->url->username? request->from->url->username:"*NULL*",
	    request->from->url->host? request->from->url->host : "*NULL*",
	    url->username? url->username : "*NULL*",
	    url->host? url->host : "*NULL*");

         sip_gen_response(request, 403 /*forbidden*/);

         return STS_FAILURE;
      }

      /* if an INVITE, rewrite body */
      if (MSG_IS_INVITE(request)) {
         sts = proxy_rewrite_invitation_body(request);
      }

      /* rewrite Contact header to represent the masqued address */
      osip_message_get_contact(request,0,&contact);
      if (contact != NULL) {
         for (i=0;i<URLMAP_SIZE;i++){
	    if (urlmap[i].active == 0) continue;
            if (compare_url(contact->url, urlmap[i].true_url)==STS_SUCCESS)
	       break;
         }
         /* found a mapping entry */
         if (i<URLMAP_SIZE) {
            char *tmp;
            DEBUGC(DBCLASS_PROXY, "rewrote Contact header %s@%s -> %s@%s",
	           (contact->url->username)? contact->url->username : "*NULL*",
                   (contact->url->host)? contact->url->host : "*NULL*",
		   urlmap[i].masq_url->username, urlmap[i].masq_url->host);
            /* remove old entry */
            osip_list_remove(request->contacts,0);
	    osip_contact_to_str(contact, &tmp);
            osip_contact_free(contact);
            /* clone the masquerading url */
	    osip_contact_init(&contact);
            osip_contact_parse(contact,tmp);
            osip_free(tmp);
	    osip_uri_free(contact->url);
            osip_uri_clone(urlmap[i].masq_url, &contact->url);
            osip_list_add(request->contacts,contact,-1);
         }     
      }

      /* add my Via header line (outbound interface)*/
      sts = sip_add_myvia(request, IF_OUTBOUND);
      if (sts == STS_FAILURE) {
         ERROR("adding my outbound via failed!");
      }

      /* if this is CANCEL/BYE request, stop RTP proxying */
      if (MSG_IS_BYE(request) || MSG_IS_CANCEL(request)) {
         rtp_stop_fwd(osip_message_get_call_id(request));
      }

      break;
   
   default:
      url=osip_message_get_uri(request);
      DEBUGC(DBCLASS_PROXY, "request [%s] from/to unregistered UA "
           "(RQ: %s@%s -> %s@%s)",
           request->sip_method? request->sip_method:"*NULL*",
	   request->from->url->username? request->from->url->username:"*NULL*",
	   request->from->url->host? request->from->url->host : "*NULL*",
	   url->username? url->username : "*NULL*",
	   url->host? url->host : "*NULL*");

/*
 * we may end up here for two reasons:
 *  1) An incomming request (from outbound) that is directed to
 *     an unknown (not registered) local UA
 *  2) an outgoing request from a local UA that is not registered.
 *
 * Case 1) we should probably answer with "404 Not Found",
 * case 2) more likely a "403 Forbidden"
 * 
 * How about "408 Request Timeout" ?
 *
 */
      sip_gen_response(request, 408 /* Request Timeout */);

      return STS_FAILURE;
   }

   /*
    * check if we need to send to an outbound proxy
    */
   if ((type == REQTYP_OUTGOING) && (configuration.outbound_proxy_host)) {
      sts = get_ip_by_host(configuration.outbound_proxy_host, &sendto_addr);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: cannot resolve outbound "
                " proxy host [%s]", configuration.outbound_proxy_host);
         return STS_FAILURE;
      }

      if (configuration.outbound_proxy_port) {
         port=configuration.outbound_proxy_port;
      } else {
         port = 5060;
      }
   } else {
      /* the host part already has been resolved above*/
      if (url->port) {
         port=atoi(url->port);
      } else {
         port=SIP_PORT;
      }
   }

   sts = osip_message_to_str(request, &buffer);
   if (sts != 0) {
      ERROR("proxy_request: osip_message_to_str failed");
      return STS_FAILURE;
   }

   sipsock_send_udp(&sip_socket, sendto_addr, port, buffer, strlen(buffer), 1); 
   osip_free (buffer);
   return STS_SUCCESS;
}


/*
 * PROXY_RESPONSE
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_response (osip_message_t *response) {
   int i;
   int sts;
   int type;
   struct in_addr sendto_addr;
   osip_via_t *via;
   osip_contact_t *contact;
   int port;
   char *buffer;

#define RESTYP_INCOMING		1
#define RESTYP_OUTGOING		2

   DEBUGC(DBCLASS_PROXY,"proxy_response");


   /* check for VIA loop, if yes, discard the request */
   sts=check_vialoop(response);
   if (sts == STS_TRUE) {
      DEBUGC(DBCLASS_PROXY,"via loop detected, ignoring response");
      /* according to the SIP RFC we are supposed to return an 482 error */
      return STS_FAILURE;
   }

   /* ALWAYS: remove my Via header line */
   sts = sip_del_myvia(response);
   if (sts == STS_FAILURE) {
      DEBUGC(DBCLASS_PROXY,"not addressed to my VIA, ignoring response");
      return STS_FAILURE;
   }

   /* figure out if this is an request coming from the outside
    * world to one of our registered clients
    */


   /* Ahhrghh...... a response seems to have NO contact information... 
    * so let's take FROM instead...
    * the TO and FROM headers are EQUAL to the request - that means 
    * they are swapped in their meaning for a response...
    */

   type = 0;
   for (i=0; i<URLMAP_SIZE; i++) {
      if (urlmap[i].active == 0) continue;

      /* incoming response ('from' == 'masq') || ('from' == 'reg') */
      if ((compare_url(response->from->url, urlmap[i].reg_url)==STS_SUCCESS) ||
          (compare_url(response->from->url, urlmap[i].masq_url)==STS_SUCCESS)) {
         type=RESTYP_INCOMING;
         DEBUGC(DBCLASS_PROXY,"incoming response for %s@%s from outbound",
	   response->from->url->username? response->from->url->username:"*NULL*",
	   response->from->url->host? response->from->url->host : "*NULL*");
	 break;
      }

      /* outgoing response ('to' == 'reg') || ('to' == 'masq' ) */
      if ((compare_url(response->to->url, urlmap[i].masq_url)==STS_SUCCESS) ||
          (compare_url(response->to->url, urlmap[i].reg_url)==STS_SUCCESS)){
         type=RESTYP_OUTGOING;
         DEBUGC(DBCLASS_PROXY,"outgoing response for %s@%s from inbound",
	   response->from->url->username? response->from->url->username:"*NULL*",
	   response->from->url->host? response->from->url->host : "*NULL*");
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
   case RESTYP_INCOMING:
      break;
   
  /*
   * from the internal masqueraded host to an external host
   */
   case RESTYP_OUTGOING:
      #define satoi atoi  /* used in MSG_TEST_CODE macro ... */
      /* If an 200 answer to an INVITE request, rewrite body */
      if ((MSG_IS_RESPONSE_FOR(response,"INVITE")) &&
          (MSG_TEST_CODE(response, 200))) {
         sts = proxy_rewrite_invitation_body(response);
      }

      /* rewrite Contact header to represent the masqued address */
      osip_message_get_contact(response,0,&contact);
      if (contact != NULL) {
         for (i=0;i<URLMAP_SIZE;i++){
	    if (urlmap[i].active == 0) continue;
            if (compare_url(contact->url, urlmap[i].true_url)==STS_SUCCESS)
	       break;
         }
         /* found a mapping entry */
         if (i<URLMAP_SIZE) {
            DEBUGC(DBCLASS_PROXY, "rewrote Contact header %s@%s -> %s@%s",
	           (contact->url->username) ? contact->url->username:"*NULL*",
                   (contact->url->host) ? contact->url->host : "*NULL*",
		   urlmap[i].masq_url->username, urlmap[i].masq_url->host);
            /* remove old entry */
            osip_list_remove(response->contacts,0);
            osip_contact_free(contact);
            /* clone the masquerading url */
	    osip_contact_init(&contact);
            osip_uri_clone(urlmap[i].masq_url, &contact->url);
            osip_list_add(response->contacts,contact,-1);
         }     
      }

      break;
   
   default:
      DEBUGC(DBCLASS_PROXY, "response from/to unregistered UA (%s@%s)",
	   response->from->url->username? response->from->url->username:"*NULL*",
	   response->from->url->host? response->from->url->host : "*NULL*");
      return STS_FAILURE;
   }

   /*
    * check if we need to send to an outbound proxy
    */
   if ((type == RESTYP_OUTGOING) && (configuration.outbound_proxy_host)) {
      /* have an outbound proxy - use it to send the packet */
      sts = get_ip_by_host(configuration.outbound_proxy_host, &sendto_addr);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: cannot resolve outbound "
                " proxy host [%s]", configuration.outbound_proxy_host);
         return STS_FAILURE;
      }

      if (configuration.outbound_proxy_port) {
         port=configuration.outbound_proxy_port;
      } else {
         port = 5060;
      }
   } else {
      /* get target address and port from VIA header */
      via = (osip_via_t *) osip_list_get (response->vias, 0);
      if (via == NULL) {
         ERROR("proxy_response: list_get via failed");
         return STS_FAILURE;
      }

      sts = get_ip_by_host(via->host, &sendto_addr);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "proxy_response: cannot resolve VIA [%s]",
                via->host);
         return STS_FAILURE;
      }

      if (via->port) {
         port=atoi(via->port);
      } else {
         port=SIP_PORT;
      }
   }

   sts = osip_message_to_str(response, &buffer);
   if (sts != 0) {
      ERROR("proxy_response: osip_message_to_str failed");
      return STS_FAILURE;
   }

   sipsock_send_udp(&sip_socket, sendto_addr, port, buffer, strlen(buffer), 1); 
   osip_free (buffer);
   return STS_SUCCESS;
}


/*
 * PROXY_REWRITE_INVITATION_BODY
 *
 * rewrites the outgoing INVITATION packet
 * 
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_rewrite_invitation_body(osip_message_t *mymsg){
   osip_body_t *body;
   sdp_message_t  *sdp;
   struct in_addr outb_addr, lcl_clnt_addr;
   int sts;
   char *bodybuff;
   char clen[8]; /* content length: probably never more than 7 digits !*/
   int outb_rtp_port, inb_clnt_port;
   int media_stream_no;
   sdp_connection_t *sdp_conn;
   sdp_media_t *sdp_med;

   /*
    * get SDP structure
    */
   sts = osip_message_get_body(mymsg, 0, &body);
   if (sts != 0) {
      ERROR("rewrite_invitation_body: no body found in message");
      return STS_FAILURE;
   }

   sts = osip_body_to_str(body, &bodybuff);
   sts = sdp_message_init(&sdp);
   sts = sdp_message_parse (sdp, bodybuff);
   osip_free(bodybuff);
   if (sts != 0) {
      ERROR("rewrite_invitation_body: unable to sdp_parse body");
      return STS_FAILURE;
   }


if (configuration.debuglevel)
{ /* just dump the buffer */
   char *tmp, *tmp2;
   sts = osip_message_get_body(mymsg, 0, &body);
   sts = osip_body_to_str(body, &tmp);
   osip_content_length_to_str(mymsg->content_length, &tmp2);
   DEBUG("Body before rewrite (clen=%s, strlen=%i):\n%s\n----",
         tmp2, strlen(tmp), tmp);
   osip_free(tmp);
   osip_free(tmp2);
}

   /*
    * RTP proxy: get ready and start forwarding
    * start forwarding for each media stream ('m=' item in SIP message)
    */
   sts = get_ip_by_host(sdp_message_c_addr_get(sdp,-1,0), &lcl_clnt_addr);
   if (sts == STS_FAILURE) {
      DEBUGC(DBCLASS_PROXY, "proxy_rewrite_invitation_body: cannot resolve "
             "m= (media) host [%s]", sdp_message_c_addr_get(sdp,-1,0));
      return STS_FAILURE;
   }

   sts = get_ip_by_ifname(configuration.outbound_if, &outb_addr);
   if (sts == STS_FAILURE) {
      ERROR("can't find outbound interface %s - configuration error?",
            configuration.inbound_if);
      return STS_FAILURE;
   }

   /*
    * rewrite c= address
    */
   sdp_conn = sdp_message_connection_get (sdp, -1, 0);
   if (sdp_conn && sdp_conn->c_addr) {
      osip_free(sdp_conn->c_addr);
      sdp_conn->c_addr=osip_malloc(HOSTNAME_SIZE);
      sprintf(sdp_conn->c_addr, "%s", utils_inet_ntoa(outb_addr));
   } else {
      ERROR("got NULL c= address record - can't rewrite");
   }
    
   /*
    * loop through all m= descritions,
    * start RTP proxy and rewrite them
    */
   for (media_stream_no=0;;media_stream_no++) {
      /* check if n'th media stream is present */
      if (sdp_message_m_port_get(sdp, media_stream_no) == NULL) break;

      /* start an RTP proxying stream */
      if (sdp_message_m_port_get(sdp, media_stream_no)) {
         inb_clnt_port=atoi(sdp_message_m_port_get(sdp, media_stream_no));

         if (inb_clnt_port > 0) {
            rtp_start_fwd(osip_message_get_call_id(mymsg), media_stream_no,
                          outb_addr, &outb_rtp_port,
	                  lcl_clnt_addr, inb_clnt_port);
            /* and rewrite the port */
            sdp_med=osip_list_get(sdp->m_medias, media_stream_no);
            if (sdp_med && sdp_med->m_port) {
               osip_free(sdp_med->m_port);
               sdp_med->m_port=osip_malloc(8);
               sprintf(sdp_med->m_port, "%i", outb_rtp_port);
               DEBUGC(DBCLASS_PROXY, "proxy_rewrite_invitation_body: "
                      "m= rewrote port to [%i]",outb_rtp_port);

            } else {
               ERROR("rewriting port in m= failed sdp_med=%p, "
                     "m_number_of_port=%p", sdp_med, sdp_med->m_port);
            }
         } // port > 0
      } else {
         /* no port defined - skip entry */
         WARN("no port defined in m=(media) stream_no=&i", media_stream_no);
         continue;
      }
   }

   /* remove old body */
   sts = osip_list_remove(mymsg->bodies, 0);
   osip_body_free(body);

   /* dump new body */
   sdp_message_to_str(sdp, &bodybuff);

   /* free sdp structure */
   sdp_message_free(sdp);

   /* include new body */
   osip_message_set_body(mymsg, bodybuff);
   osip_free(bodybuff);

   /* free content length resource and include new one*/
   osip_content_length_free(mymsg->content_length);
   mymsg->content_length=NULL;
   sprintf(clen,"%i",strlen(bodybuff));
   sts = osip_message_set_content_length(mymsg, clen);

if (configuration.debuglevel)
{ /* just dump the buffer */
   char *tmp, *tmp2;
   sts = osip_message_get_body(mymsg, 0, &body);
   sts = osip_body_to_str(body, &tmp);
   osip_content_length_to_str(mymsg->content_length, &tmp2);
   DEBUG("Body after rewrite (clen=%s, strlen=%i):\n%s\n----",
         tmp2, strlen(tmp), tmp);
   osip_free(tmp);
   osip_free(tmp2);
}
   return STS_SUCCESS;
}


/*
 * PROXY_REWRITE_INVITATION_BODY
 *
 * rewrites the outgoing INVITATION packet
 * 
 * RETURNS
 *	STS_SUCCESS on success
 */
int proxy_rewrite_request_uri(osip_message_t *mymsg, int idx){
   char *host;
   char *port;
   osip_uri_t *url;

   DEBUGC(DBCLASS_PROXY,"rewriting incoming Request URI");
   url=osip_message_get_uri(mymsg);
   osip_free(url->host);url->host=NULL;

   /* set the true host */
   if(urlmap[idx].true_url->host) {
      host = (char *)malloc(strlen(urlmap[idx].true_url->host)+1);
      memcpy(host, urlmap[idx].true_url->host, strlen(urlmap[idx].true_url->host));
      host[strlen(urlmap[idx].true_url->host)]='\0';
      osip_uri_set_host(url, host);
   }

   /* set the true port */
   if(urlmap[idx].true_url->port) {
      port = (char *)malloc(strlen(urlmap[idx].true_url->port)+1);
      memcpy(port, urlmap[idx].true_url->port, strlen(urlmap[idx].true_url->port));
      port[strlen(urlmap[idx].true_url->port)]='\0';
      osip_uri_set_port(url, port);
   }
   return STS_SUCCESS;
}

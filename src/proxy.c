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

#ifdef HAVE_OSIP2
   #include <osip2/smsg.h>
   #include <osip2/sdp.h>
#else
   #include <osip/smsg.h>
   #include <osip/sdp.h>
#endif

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
int proxy_request (sip_t *request) {
   int i;
   int sts;
   int type;
   struct in_addr sendto_addr;
   contact_t *contact;
   url_t *url;
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

      /* incoming request ('to' == 'masq') */
      if (compare_url(request->to->url, urlmap[i].masq_url)==STS_SUCCESS) {
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
   header_t *header_ua;

   url=msg_geturi(request);
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
     msg_getcall_id(request)->number, msg_getcall_id(request)->host);
#endif
         /* stop the RTP proxying stream */
         rtp_stop_fwd(msg_getcall_id(request), 0);
      }

      break;
   
  /*
   * from the internal masqueraded host to an external host
   */
   case REQTYP_OUTGOING:
      /* get destination address */
      url=msg_geturi(request);

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
	    request->strtline->sipmethod? request->strtline->sipmethod:"*NULL*",
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
      msg_getcontact(request,0,&contact);
      if (contact != NULL) {
         for (i=0;i<URLMAP_SIZE;i++){
	    if (urlmap[i].active == 0) continue;
            if (compare_url(contact->url, urlmap[i].true_url)==STS_SUCCESS)
	       break;
         }
         /* found a mapping entry */
         if (i<URLMAP_SIZE) {
            DEBUGC(DBCLASS_PROXY, "rewrote Contact header %s@%s -> %s@%s",
	           (contact->url->username)? contact->url->username : "*NULL*",
                   (contact->url->host)? contact->url->host : "*NULL*",
		   urlmap[i].masq_url->username, urlmap[i].masq_url->host);
            /* remove old entry */
            list_remove(request->contacts,0);
            contact_free(contact);
            free(contact);
            /* clone the masquerading url */
	    contact_init(&contact);
            url_clone(urlmap[i].masq_url, &contact->url);
            list_add(request->contacts,contact,-1);
         }     
      }

      /* add my Via header line (outbound interface)*/
      sts = sip_add_myvia(request, IF_OUTBOUND);
      if (sts == STS_FAILURE) {
         ERROR("adding my outbound via failed!");
      }

      /* if this is CANCEL/BYE request, stop RTP proxying */
      if (MSG_IS_BYE(request) || MSG_IS_CANCEL(request)) {
         rtp_stop_fwd(msg_getcall_id(request), 0);
      }

      break;
   
   default:
      url=msg_geturi(request);
      DEBUGC(DBCLASS_PROXY, "request [%s] from/to unregistered UA "
           "(RQ: %s@%s -> %s@%s)",
           request->strtline->sipmethod? request->strtline->sipmethod:"*NULL*",
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


   sts = msg_2char(request, &buffer);
   if (sts != 0) {
      ERROR("proxy_request: msg_2char failed");
      return STS_FAILURE;
   }

   /* send to destination */
   if (url->port) {
      port=atoi(url->port);
   } else {
      port=SIP_PORT;
   }

   sipsock_send_udp(&sip_socket, sendto_addr, port, buffer, strlen(buffer), 1); 
   free (buffer);
   return STS_SUCCESS;
}


/*
 * PROXY_RESPONSE
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_response (sip_t *response) {
   int i;
   int sts;
   int type;
   struct in_addr addr;
   via_t *via;
   contact_t *contact;
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


   /* Ahhrghh...... an response seems to have NO contact information... 
    * so let's take FROM instead...
    * the TO and FROM headers are EQUAL to the request - that means 
    * they are swapped in their meaning for a response...
    */

   type = 0;
   for (i=0; i<URLMAP_SIZE; i++) {
      if (urlmap[i].active == 0) continue;


      /* incoming response ('from' == 'masq') */
      if (compare_url(response->from->url, urlmap[i].masq_url)==STS_SUCCESS) {
         type=RESTYP_INCOMING;
         DEBUGC(DBCLASS_PROXY,"incoming response for %s@%s from outbound",
	   response->from->url->username? response->from->url->username:"*NULL*",
	   response->from->url->host? response->from->url->host : "*NULL*");
	 break;
      }

      /* outgoing response ('to' == 'reg') */
      if (compare_url(response->to->url, urlmap[i].masq_url)==STS_SUCCESS) {
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
      if ((MSG_IS_RESPONSEFOR(response,"INVITE")) &&
          (MSG_TEST_CODE(response, 200))) {
         sts = proxy_rewrite_invitation_body(response);
      }

      /* rewrite Contact header to represent the masqued address */
      msg_getcontact(response,0,&contact);
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
            list_remove(response->contacts,0);
            contact_free(contact);
            free(contact);
            /* clone the masquerading url */
	    contact_init(&contact);
            url_clone(urlmap[i].masq_url, &contact->url);
            list_add(response->contacts,contact,-1);
         }     
      }

      break;
   
   default:
      DEBUGC(DBCLASS_PROXY, "response from/to unregistered UA (%s@%s)",
	   response->from->url->username? response->from->url->username:"*NULL*",
	   response->from->url->host? response->from->url->host : "*NULL*");
      return STS_FAILURE;
   }

   /* get target address from VIA header */
   via = (via_t *) list_get (response->vias, 0);
   if (via == NULL) {
      ERROR("proxy_response: list_get via failed");
      return STS_FAILURE;
   }

   sts = get_ip_by_host(via->host, &addr);
   if (sts == STS_FAILURE) {
      DEBUGC(DBCLASS_PROXY, "proxy_response: cannot resolve via [%s]",
             via->host);
      return STS_FAILURE;
   }

   sts = msg_2char(response, &buffer);
   if (sts != 0) {
      ERROR("proxy_response: msg_2char failed");
      return STS_FAILURE;
   }

   /* send to destination */
   if (via->port) {
      port=atoi(via->port);
   } else {
      port=SIP_PORT;
   }

   sipsock_send_udp(&sip_socket, addr, port, buffer, strlen(buffer), 1); 
   free (buffer);
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
int proxy_rewrite_invitation_body(sip_t *mymsg){
   body_t *body;
   sdp_t  *sdp;
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
   sts = msg_getbody(mymsg, 0, &body);
   if (sts != 0) {
      ERROR("rewrite_invitation_body: no body found in message");
      return STS_FAILURE;
   }

   sts = body_2char(body, &bodybuff);
   sts = sdp_init(&sdp);
   sts = sdp_parse (sdp, bodybuff);
   free(bodybuff);
   if (sts != 0) {
      ERROR("rewrite_invitation_body: unable to sdp_parse body");
      return STS_FAILURE;
   }


if (configuration.debuglevel)
{ /* just dump the buffer */
   char *tmp, *tmp2;
   sts = msg_getbody(mymsg, 0, &body);
   sts = body_2char(body, &tmp);
   content_length_2char(mymsg->contentlength, &tmp2);
   DEBUG("Body before rewrite (clen=%s, strlen=%i):\n%s\n----",
         tmp2, strlen(tmp), tmp);
   free(tmp);
   free(tmp2);
}

   /*
    * RTP proxy: get ready and start forwarding
    * start forwarding for each media stream ('m=' item in SIP message)
    */
   sts = get_ip_by_host(sdp_c_addr_get(sdp,-1,0), &lcl_clnt_addr);
   if (sts == STS_FAILURE) {
      DEBUGC(DBCLASS_PROXY, "proxy_rewrite_invitation_body: cannot resolve "
             "m= (media) host [%s]", sdp_c_addr_get(sdp,-1,0));
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
   sdp_conn = sdp_connection_get (sdp, -1, 0);
   if (sdp_conn && sdp_conn->c_addr) {
      free(sdp_conn->c_addr);
      sdp_conn->c_addr=malloc(HOSTNAME_SIZE);
      sprintf(sdp_conn->c_addr, "%s", inet_ntoa(outb_addr));
   } else {
      ERROR("got NULL c= address record - can't rewrite");
   }
    
   /*
    * loop through all m= descritions,
    * start RTP proxy and rewrite them
    */
   for (media_stream_no=0;;media_stream_no++) {
      /* check if n'th media stream is present */
      if (sdp_m_port_get(sdp, media_stream_no) == NULL) break;

      /* start an RTP proxying stream */
      if (sdp_m_port_get(sdp, media_stream_no)) {
         inb_clnt_port=atoi(sdp_m_port_get(sdp, media_stream_no));
         rtp_start_fwd(msg_getcall_id(mymsg), media_stream_no,
                       outb_addr, &outb_rtp_port,
	               lcl_clnt_addr, inb_clnt_port);
         /* and rewrite the port */
         sdp_med=list_get(sdp->m_medias, media_stream_no);
         if (sdp_med && sdp_med->m_port) {
            free(sdp_med->m_port);
            sdp_med->m_port=malloc(8);
            sprintf(sdp_med->m_port, "%i", outb_rtp_port);
            DEBUGC(DBCLASS_PROXY, "proxy_rewrite_invitation_body: "
                   "m= rewrote port to [%i]",outb_rtp_port);

         } else {
            ERROR("rewriting port in m= failed sdp_med=%p, "
                  "m_number_of_port=%p", sdp_med, sdp_med->m_port);
         }
      } else {
         /* no port defined - skip entry */
         WARN("no port defined in m=(media) stream_no=&i", media_stream_no);
         continue;
      }
   }

   /* remove old body */
   sts = list_remove(mymsg->bodies, 0);
   body_free(body);
   free(body);

   /* dump new body */
   sdp_2char(sdp, &bodybuff);

   /* free sdp structure */
   sdp_free(sdp);
   free(sdp);

   /* include new body */
   msg_setbody(mymsg, bodybuff);
   free(bodybuff);

   /* free content length resource and include new one*/
   content_length_free(mymsg->contentlength);
   free(mymsg->contentlength);
   mymsg->contentlength=NULL;
   sprintf(clen,"%i",strlen(bodybuff));
   sts = msg_setcontent_length(mymsg, clen);

if (configuration.debuglevel)
{ /* just dump the buffer */
   char *tmp, *tmp2;
   sts = msg_getbody(mymsg, 0, &body);
   sts = body_2char(body, &tmp);
   content_length_2char(mymsg->contentlength, &tmp2);
   DEBUG("Body after rewrite (clen=%s, strlen=%i):\n%s\n----",
         tmp2, strlen(tmp), tmp);
   free(tmp);
   free(tmp2);
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
int proxy_rewrite_request_uri(sip_t *mymsg, int idx){
   char *host;
   char *port;
   url_t *url;

   DEBUGC(DBCLASS_PROXY,"rewriting incoming Request URI");
   url=msg_geturi(mymsg);
   free(url->host);url->host=NULL;

   /* set the true host */
   if(urlmap[idx].true_url->host) {
      host = (char *)malloc(strlen(urlmap[idx].true_url->host)+1);
      memcpy(host, urlmap[idx].true_url->host, strlen(urlmap[idx].true_url->host));
      host[strlen(urlmap[idx].true_url->host)]='\0';
      url_sethost(url, host);
   }

   /* set the true port */
   if(urlmap[idx].true_url->port) {
      port = (char *)malloc(strlen(urlmap[idx].true_url->port)+1);
      memcpy(port, urlmap[idx].true_url->port, strlen(urlmap[idx].true_url->port));
      port[strlen(urlmap[idx].true_url->port)]='\0';
      url_setport(url, port);
   }
   return STS_SUCCESS;
}

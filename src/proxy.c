/* -*- Mode: C; c-basic-offset: 3 -*-
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

static char const ident[]="$Id$";

/* configuration storage */
extern struct siproxd_config configuration;	/* defined in siproxd.c */

extern struct urlmap_s urlmap[];		/* URL mapping table     */
extern struct lcl_if_s local_addresses;


/*
 * PROXY_REQUEST
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 *
 * RFC3261
 *    Section 16.3: Proxy Behavior - Request Validation
 *    1. Reasonable Syntax
 *    2. URI scheme
 *    3. Max-Forwards
 *    4. (Optional) Loop Detection
 *    5. Proxy-Require
 *    6. Proxy-Authorization
 *
 *    Section 16.6: Proxy Behavior - Request Forwarding
 *    1.  Make a copy of the received request
 *    2.  Update the Request-URI
 *    3.  Update the Max-Forwards header field
 *    4.  Optionally add a Record-route header field value
 *    5.  Optionally add additional header fields
 *    6.  Postprocess routing information
 *    7.  Determine the next-hop address, port, and transport
 *    8.  Add a Via header field value
 *    9.  Add a Content-Length header field if necessary
 *    10. Forward the new request
 *    11. Set timer C
 */
int proxy_request (sip_ticket_t *ticket) {
   int i;
   int sts;
   int type;
   struct in_addr sendto_addr;
   osip_uri_t *url;
   int port;
   char *buffer;
   osip_message_t *request;
   struct sockaddr_in *from;

#define REQTYP_INCOMING		1
#define REQTYP_OUTGOING		2

   DEBUGC(DBCLASS_PROXY,"proxy_request");

   if (ticket==NULL) {
      ERROR("proxy_request: called with NULL ticket");
      return STS_FAILURE;
   }

   request=ticket->sipmsg;
   from=&ticket->from;

   /*
    * RFC 3261, Section 16.4
    * Proxy Behavior - Route Information Preprocessing
    * (process Route header)
    */
/*
   The proxy MUST inspect the Request-URI of the request.  If the
   Request-URI of the request contains a value this proxy previously
   placed into a Record-Route header field (see Section 16.6 item 4),
   the proxy MUST replace the Request-URI in the request with the last
   value from the Route header field, and remove that value from the
   Route header field.  The proxy MUST then proceed as if it received
   this modified request.

   NOT IMPLEMENTED*/


   /*
    * Check if I am listed at the topmost Route header (if any Route
    * header is existing at all). If so, remove it from the list and
    * rewrite the request URI to point to the now topmost Route.
    */
   if (request->routes && !osip_list_eol(request->routes, 0)) {
      struct in_addr addr1, addr2, addr3;
      osip_route_t *route;
      
      route = (osip_route_t *) osip_list_get(request->routes, 0);
      
      sts = get_ip_by_host(route->url->host, &addr1);
      if (get_ip_by_ifname(configuration.inbound_if, &addr2) != STS_SUCCESS) {
         ERROR("can't find inbound interface %s - configuration error?",
               configuration.inbound_if);
         return STS_FAILURE;
      }
      if (get_ip_by_ifname(configuration.outbound_if, &addr3)!= STS_SUCCESS) {
         ERROR("can't find outbound interface %s - configuration error?",
               configuration.outbound_if);
         return STS_FAILURE;
      }

      /* my own route header? */
      if ((sts == STS_SUCCESS) &&
          ((memcmp(&addr1, &addr2, sizeof(addr1)) == 0) ||
           (memcmp(&addr1, &addr3, sizeof(addr1)) == 0)) &&
           (route->url->port ?
               configuration.sip_listen_port == atoi(route->url->port):
               configuration.sip_listen_port == SIP_PORT)) {
         osip_list_remove(request->routes, 0);
         osip_route_free(route);
         /* request->routes will be freed by osip_message_free() */
         DEBUGC(DBCLASS_PROXY, "removed Route header pointing to myself");
      }
   }
      

   /*
    * figure out whether this is an incoming or outgoing request
    * by doing a lookup in the registration table.
    */
#define _OLD_DIRECTION_EVALUATION 0
#if _OLD_DIRECTION_EVALUATION
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
#else
   type = 0;
   /*
    * did I receive the telegram from a REGISTERED host?
    * -> it must be an OUTGOING request
    */
   for (i=0; i<URLMAP_SIZE; i++) {
      struct in_addr tmp_addr;

      if (urlmap[i].active == 0) continue;
      if (get_ip_by_host(urlmap[i].true_url->host, &tmp_addr) == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: cannot resolve host [%s]",
             urlmap[i].true_url);
      } else {
         DEBUGC(DBCLASS_PROXY, "proxy_request: reghost:%s ip:%s",
                urlmap[i].true_url->host, utils_inet_ntoa(from->sin_addr));
         if (memcmp(&tmp_addr, &from->sin_addr, sizeof(tmp_addr)) == 0) {
            type=REQTYP_OUTGOING;
	    break;
         }
      }
   }

   /*
    * is the telegram directed to an internally registered host?
    * -> it must be an INCOMING request
    */
   if (type == 0) for (i=0; i<URLMAP_SIZE; i++) {
      if (urlmap[i].active == 0) continue;
      /* RFC3261:
       * To contains a display name (Bob) and a SIP or SIPS URI
       * (sip:bob@biloxi.com) towards which the request was originally
       * directed.  Display names are described in RFC 2822 [3].
       */

      /* So this means, that we must check the SIP URI supplied with the
       * INVITE method, as this points to the real wanted target.
       * Q: does there exist a situation where the SIP URI itself does
       *    point to "somewhere" but the To: points to the correct UA?
       * So for now, we just look at both of them (SIP URI and To: header)
       */

      /* incoming request (SIP URI == 'masq') || ((SIP URI == 'reg') && !REGISTER)*/
      if ((compare_url(request->req_uri, urlmap[i].masq_url)==STS_SUCCESS) ||
          (!MSG_IS_REGISTER(request) &&
           (compare_url(request->req_uri, urlmap[i].reg_url)==STS_SUCCESS))) {
         type=REQTYP_INCOMING;
	 break;
      }
      /* incoming request ('to' == 'masq') || (('to' == 'reg') && !REGISTER)*/
      if ((compare_url(request->to->url, urlmap[i].masq_url)==STS_SUCCESS) ||
          (!MSG_IS_REGISTER(request) &&
           (compare_url(request->to->url, urlmap[i].reg_url)==STS_SUCCESS))) {
         type=REQTYP_INCOMING;
	 break;
      }
   }
#endif


   /*
    * logging of passing calls
    */
   if (configuration.log_calls) {
      osip_uri_t *cont_url = NULL;
      if (!osip_list_eol(request->contacts, 0))
         cont_url = ((osip_contact_t*)(request->contacts->node->element))->url;
      
      /* INVITE */
      if (MSG_IS_INVITE(request)) {
         if (cont_url) {
            INFO("%s Call from: %s@%s",
                 (type==REQTYP_INCOMING) ? "Incoming":"Outgoing",
                 cont_url->username ? cont_url->username:"*NULL*",
                 cont_url->host ? cont_url->host : "*NULL*");
         } else {
            INFO("%s Call (w/o contact header) from: %s@%s",
                 (type==REQTYP_INCOMING) ? "Incoming":"Outgoing",
	         request->from->url->username ? 
                    request->from->url->username:"*NULL*",
	         request->from->url->host ? 
                    request->from->url->host : "*NULL*");
         }
      /* BYE / CANCEL */
      } else if (MSG_IS_BYE(request) || MSG_IS_CANCEL(request)) {
         if (cont_url) {
            INFO("Ending Call from: %s@%s",
                 cont_url->username ? cont_url->username:"*NULL*",
                 cont_url->host ? cont_url->host : "*NULL*");
         } else {
            INFO("Ending Call (w/o contact header) from: %s@%s",
	         request->from->url->username ? 
                    request->from->url->username:"*NULL*",
	         request->from->url->host ? 
                    request->from->url->host : "*NULL*");
         }
      }
   } /* log_calls */


   /*
    * RFC 3261, Section 16.6 step 1
    * Proxy Behavior - Request Forwarding - Make a copy
    */
   /* nothing to do here, copy is ready in 'request'*/

   /* get destination address */
   url=osip_message_get_uri(request);

   switch (type) {
  /*
   * from an external host to the internal masqueraded host
   */
   case REQTYP_INCOMING:
      DEBUGC(DBCLASS_PROXY,"incoming request from %s@%s from outbound",
	request->from->url->username? request->from->url->username:"*NULL*",
        request->from->url->host? request->from->url->host: "*NULL*");

      /*
       * RFC 3261, Section 16.6 step 2
       * Proxy Behavior - Request Forwarding - Request-URI
       * (rewrite request URI to point to the real host)
       */
      /* 'i' still holds the valid index into the URLMAP table */
      if (check_rewrite_rq_uri(request) == STS_TRUE) {
         proxy_rewrite_request_uri(request, i);
      }

      /* if this is CANCEL/BYE request, stop RTP proxying */
      if (MSG_IS_BYE(request) || MSG_IS_CANCEL(request)) {
         /* stop the RTP proxying stream(s) */
         rtp_stop_fwd(osip_message_get_call_id(request), DIR_INCOMING);
         rtp_stop_fwd(osip_message_get_call_id(request), DIR_OUTGOING);

      /* check for incoming request */
      } else if (MSG_IS_INVITE(request)) {
         /* First, rewrite the body */
         if (configuration.rtp_proxy_enable == 1) {
            sts = proxy_rewrite_invitation_body(request, DIR_INCOMING);
         }

         /*
          * Note: Incoming requests have no need to rewrite Contact
          * header - as we are not masquerading something there
          */

      }
      break;
   
  /*
   * from the internal masqueraded host to an external host
   */
   case REQTYP_OUTGOING:
      DEBUGC(DBCLASS_PROXY,"outgoing request from %s@%s from inbound",
	request->from->url->username? request->from->url->username:"*NULL*",
        request->from->url->host? request->from->url->host: "*NULL*");

      /*
       * RFC 3261, Section 16.6 step 2
       * Proxy Behavior - Request Forwarding - Request-URI
       */
      /* nothing to do for an outgoing request */


      /* if it is addressed to myself, then it must be some request
       * method that I as a proxy do not support. Reject */
#if 0
/* careful - an internal UA might send an request to another internal UA.
   This would be caught here, so don't do this. This situation should be
   caught in the default part of the CASE statement below */
      if (is_sipuri_local(ticket) == STS_TRUE) {
         WARN("unsupported request [%s] directed to proxy from %s@%s -> %s@%s",
	    request->sip_method? request->sip_method:"*NULL*",
	    request->from->url->username? request->from->url->username:"*NULL*",
	    request->from->url->host? request->from->url->host : "*NULL*",
	    url->username? url->username : "*NULL*",
	    url->host? url->host : "*NULL*");

         sip_gen_response(ticket, 403 /*forbidden*/);

         return STS_FAILURE;
      }
#endif

      /* rewrite Contact header to represent the masqued address */
      sip_rewrite_contact(ticket, DIR_OUTGOING);

      /* if an INVITE, rewrite body */
      if (MSG_IS_INVITE(request)) {
         sts = proxy_rewrite_invitation_body(request, DIR_OUTGOING);
      }

      /* if this is CANCEL/BYE request, stop RTP proxying */
      if (MSG_IS_BYE(request) || MSG_IS_CANCEL(request)) {
         /* stop the RTP proxying stream(s) */
         rtp_stop_fwd(osip_message_get_call_id(request), DIR_INCOMING);
         rtp_stop_fwd(osip_message_get_call_id(request), DIR_OUTGOING);
      }

      break;
   
   default:
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
      sip_gen_response(ticket, 408 /* Request Timeout */);

      return STS_FAILURE;
   }


   /*
    * RFC 3261, Section 16.6 step 3
    * Proxy Behavior - Request Forwarding - Max-Forwards
    * (if Max-Forwards header exists, decrement by one, if it does not
    * exist, add a new one with value SHOULD be 70)
    */
   {
   osip_header_t *max_forwards;
   int forwards_count = DEFAULT_MAXFWD;
   char mfwd[8];

   osip_message_get_max_forwards(request, 0, &max_forwards);
   if (max_forwards == NULL) {
      sprintf(mfwd, "%i", forwards_count);
      osip_message_set_max_forwards(request, mfwd);
   } else {
      if (max_forwards->hvalue) {
         forwards_count = atoi(max_forwards->hvalue);
         forwards_count -=1;
         osip_free (max_forwards->hvalue);
      }

      sprintf(mfwd, "%i", forwards_count);
      max_forwards->hvalue = osip_strdup(mfwd);
   }

   DEBUGC(DBCLASS_PROXY,"setting Max-Forwards=%s",mfwd);
   }

   /*
    * RFC 3261, Section 16.6 step 4
    * Proxy Behavior - Request Forwarding - Add a Record-route header
    */
#if 0
/* NOT IMPLEMENTED - this requires proper implementation of
   the Route headers first. */
   {
   struct in_addr addr;
   osip_record_route_t *r_route;
   osip_uri_t *uri_of_proxy;

   /*
    * get the IP address of the interface where I'm going to
    * send out this request
    */
   switch (type) {
   case REQTYP_INCOMING:
      if (get_ip_by_ifname(configuration.inbound_if, &addr) != STS_SUCCESS) {
         ERROR("can't find inbound interface %s - configuration error?",
               configuration.inbound_if);
         return STS_FAILURE;
      }
      break;
   case REQTYP_OUTGOING:
      if (get_ip_by_ifname(configuration.outbound_if, &addr) != STS_SUCCESS) {
         ERROR("can't find outbound interface %s - configuration error?",
               configuration.outbound_if);
         return STS_FAILURE;
      }
      break;
   default:
      ERROR("Oops, never should end up here (type=%i)", type);
      return STS_FAILURE;
   }

   sts = osip_record_route_init(&r_route);
   if (sts == 0) {
      sts = osip_uri_init(&uri_of_proxy);
      if (sts == 0) {
         char tmp[8];

         /* host name / IP */
         osip_uri_set_host(uri_of_proxy, osip_strdup(utils_inet_ntoa(addr)));

         /* port number */
         sprintf(tmp, "%i", configuration.sip_listen_port);
         osip_uri_set_port(uri_of_proxy, osip_strdup(tmp));

         /* 'lr' parameter */
         osip_uri_uparam_add(uri_of_proxy, "lr", NULL);

         osip_record_route_set_url(r_route, uri_of_proxy);

         /* insert before all other record-route */
         osip_list_add (request->record_routes, r_route, 0);
      } else {
          osip_record_route_free (r_route);
          osip_free (r_route);
      } /* if url_init */
   } /* if record route init */

   }
#endif

   /*
    * RFC 3261, Section 16.6 step 5
    * Proxy Behavior - Request Forwarding - Add Additional Header Fields
    */
   /* NOT IMPLEMENTED (optional) */


   /*
    * RFC 3261, Section 16.6 step 6
    * Proxy Behavior - Request Forwarding - Postprocess routing information
    *
    * If the copy contains a Route header field, the proxy MUST
    * inspect the URI in its first value.  If that URI does not
    * contain an lr parameter, the proxy MUST modify the copy as
    * follows:
    *
    * -  The proxy MUST place the Request-URI into the Route header
    *    field as the last value.
    *
    * -  The proxy MUST then place the first Route header field value
    *    into the Request-URI and remove that value from the Route
    *    header field.
    */
#if 0
/* we are not a real proxy - and from the outside we look like an UA.
So we should not fiddle around with the Route headers.
We should use the first Route header to send the packet to
(RFC3261, section 8.1.2) */
   if (request->routes && !osip_list_eol(request->routes, 0)) {
      osip_route_t *route=NULL;
      osip_uri_param_t *param=NULL;

      route = (osip_route_t *) osip_list_get(request->routes, 0);
      if (route->url) {
         /* check for non existing lr parameter */
         if (osip_uri_uparam_get_byname(route->url, "lr", &param) != 0) {
            osip_route_t *new_route=NULL;
            url=osip_message_get_uri(request);

            /* push Request URI into Route header list at the last position */
            osip_route_init(&new_route);
            osip_uri_clone(url, &new_route->url);
            osip_list_add(request->routes, new_route, -1);
            

            /* rewrite request URI to now topmost Route header */
            DEBUGC(DBCLASS_PROXY, "Route header w/o 'lr': rewriting request "
                   "URI from %s to %s", url->host, route->url->host);
            osip_uri_free(url);
            url=NULL;
            osip_uri_clone(route->url, &url);
            /* remove first Route header from list & free */
            osip_list_remove(request->routes, 0);
            osip_route_free(route);
            route = NULL;
         }
      }
   }
#endif

   /*
    * RFC 3261, Section 16.6 step 7
    * Proxy Behavior - Determine Next-Hop Address
    */
   if ((type == REQTYP_OUTGOING) && (configuration.outbound_proxy_host)) {
      /* I have an outbound proxy configured */
      sts = get_ip_by_host(configuration.outbound_proxy_host, &sendto_addr);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: cannot resolve outbound "
                " proxy host [%s]", configuration.outbound_proxy_host);
         return STS_FAILURE;
      }

      if (configuration.outbound_proxy_port) {
         port=configuration.outbound_proxy_port;
      } else {
         port = SIP_PORT;
      }
   } else if ((type == REQTYP_OUTGOING) && 
              (request->routes && !osip_list_eol(request->routes, 0))) {
      /* get the destination from the Route Header */
      osip_route_t *route=NULL;
      route = (osip_route_t *) osip_list_get(request->routes, 0);
      if (route==NULL || route->url==NULL || route->url->host==NULL) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: got broken Route header "
                "- discarding packet");
         return STS_FAILURE;
      }

      sts = get_ip_by_host(route->url->host, &sendto_addr);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: cannot resolve Route URI [%s]",
                route->url->host);
         return STS_FAILURE;
      }

      if (route->url->port) {
         port=atoi(route->url->port);
      } else {
         port=SIP_PORT;
      }
   } else {
      /* get the destination from the SIP URI */
      sts = get_ip_by_host(url->host, &sendto_addr);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: cannot resolve URI [%s]",
                url->host);
         return STS_FAILURE;
      }

      if (url->port) {
         port=atoi(url->port);
      } else {
         port=SIP_PORT;
      }
   }

   /*
    * RFC 3261, Section 16.6 step 8
    * Proxy Behavior - Add a Via header field value
    */
   /* add my Via header line (outbound interface)*/
   if (type == REQTYP_INCOMING) {
      sts = sip_add_myvia(ticket, IF_INBOUND);
      if (sts == STS_FAILURE) {
         ERROR("adding my inbound via failed!");
      }
   } else {
      sts = sip_add_myvia(ticket, IF_OUTBOUND);
      if (sts == STS_FAILURE) {
         ERROR("adding my outbound via failed!");
         return STS_FAILURE;
      }
   }
  /*
   * RFC 3261, Section 16.6 step 9
   * Proxy Behavior - Add a Content-Length header field if necessary
   */
  /* not necessary, already in message and we do not support TCP */

  /*
   * RFC 3261, Section 16.6 step 10
   * Proxy Behavior - Forward the new request
   */
   sts = osip_message_to_str(request, &buffer);
   if (sts != 0) {
      ERROR("proxy_request: osip_message_to_str failed");
      return STS_FAILURE;
   }

   sipsock_send(sendto_addr, port, ticket->protocol,
                buffer, strlen(buffer)); 
   osip_free (buffer);

  /*
   * RFC 3261, Section 16.6 step 11
   * Proxy Behavior - Set timer C
   */
  /* NOT IMPLEMENTED - does this really apply for stateless proxies? */

   return STS_SUCCESS;
}


/*
 * PROXY_RESPONSE
 *
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_response (sip_ticket_t *ticket) {
   int i;
   int sts;
   int type;
   struct in_addr sendto_addr;
   osip_via_t *via;
   int port;
   char *buffer;
   osip_message_t *response;
   struct sockaddr_in *from;

#define RESTYP_INCOMING		1
#define RESTYP_OUTGOING		2

   DEBUGC(DBCLASS_PROXY,"proxy_response");

   if (ticket==NULL) {
      ERROR("proxy_response: called with NULL ticket");
      return STS_FAILURE;
   }

   response=ticket->sipmsg;
   from=&ticket->from;

   /*
    * RFC 3261, Section 16.11
    * Proxy Behavior - Remove my Via header field value
    */
   /* remove my Via header line */
   sts = sip_del_myvia(ticket);
   if (sts == STS_FAILURE) {
      DEBUGC(DBCLASS_PROXY,"not addressed to my VIA, ignoring response");
      return STS_FAILURE;
   }

   /*
    * figure out if this is an request coming from the outside
    * world to one of our registered clients
    */

   /* Ahhrghh...... a response seems to have NO contact information... 
    * so let's take FROM instead...
    * the TO and FROM headers are EQUAL to the request - that means 
    * they are swapped in their meaning for a response...
    */

#if _OLD_DIRECTION_EVALUATION
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
	        response->from->url->username ?
                   response->from->url->username : "*NULL*",
	        response->from->url->host ? 
                   response->from->url->host : "*NULL*");
	 break;
      }
   }
#else
   type = 0;
   /*
    * did I receive the telegram from a REGISTERED host?
    * -> it must be an OUTGOING response
    */
   for (i=0; i<URLMAP_SIZE; i++) {
      struct in_addr tmp_addr;
      if (urlmap[i].active == 0) continue;

      if (get_ip_by_host(urlmap[i].true_url->host, &tmp_addr) == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: cannot resolve host [%s]",
             urlmap[i].true_url);
      } else {
         DEBUGC(DBCLASS_PROXY, "proxy_request: reghost:%s ip:%s",
                urlmap[i].true_url->host, utils_inet_ntoa(from->sin_addr));
         if (memcmp(&tmp_addr, &from->sin_addr, sizeof(tmp_addr)) == 0) {
            type=RESTYP_OUTGOING;
	    break;
         }
      }
   }
   /*
    * is the telegram directed to an internal registered host?
    * -> it must be an INCOMING response
    */
   if (type == 0) for (i=0; i<URLMAP_SIZE; i++) {
      if (urlmap[i].active == 0) continue;
      /* incoming response ('from' == 'masq') || ('from' == 'reg') */
      if ((compare_url(response->from->url, urlmap[i].reg_url)==STS_SUCCESS) ||
          (compare_url(response->from->url, urlmap[i].masq_url)==STS_SUCCESS)) {
         type=RESTYP_INCOMING;
	 break;
      }
   }
#endif


/*
 * ok, we got a response that we are allowed to process.
 */
   switch (type) {
  /*
   * from an external host to the internal masqueraded host
   */
   case RESTYP_INCOMING:
      DEBUGC(DBCLASS_PROXY,"incoming response for %s@%s from outbound",
	response->from->url->username? response->from->url->username:"*NULL*",
	response->from->url->host? response->from->url->host : "*NULL*");

      /*
       * Response for INVITE - deal with RTP data in body and
       *                       start RTP proxy stream(s)
       */
      if ((MSG_IS_RESPONSE_FOR(response,"INVITE")) &&
          ((MSG_TEST_CODE(response, 200)) || 
           (MSG_TEST_CODE(response, 183)))) {
         if (configuration.rtp_proxy_enable == 1) {
            sts = proxy_rewrite_invitation_body(response, DIR_INCOMING);
         }
      }

      /*
       * Response for REGISTER - special handling of Contact header
       */
      if (MSG_IS_RESPONSE_FOR(response,"REGISTER")) {
         /*
          * REGISTER returns *my* Contact header information.
          * Rewrite Contact header back to represent the true address.
          * Other responses do return the Contact header of the sender.
          */
         sip_rewrite_contact(ticket, DIR_INCOMING);
      }

      /* 
       * Response for SUBSCRIBE
       *
       * HACK for Grandstream SIP phones (with newer firmware like 1.0.4.40):
       *   They send a SUBSCRIBE request to the registration server. In
       *   case of beeing registering directly to siproxd, this request of
       *   course will eventually be forwarded back to the same UA.
       *   Grandstream then does reply with an '202' response (A 202
       *   response merely indicates that the subscription has been
       *   understood, and that authorization may or may not have been
       *   granted), which then of course is forwarded back to the phone.
       *   Ans it seems that the Grandstream can *not* *handle* this
       *   response, as it immediately sends another SUBSCRIBE request.
       *   And this games goes on and on and on...
       *
       *   As a workaround we will transform any 202 response to a
       *   '404 unknown destination'
       *   
       */
{
      osip_header_t *ua_hdr=NULL;
      osip_message_get_user_agent(response, 0, &ua_hdr);
      if (ua_hdr && ua_hdr->hvalue &&
          (osip_strncasecmp(ua_hdr->hvalue,"grandstream", 11)==0) &&
          (MSG_IS_RESPONSE_FOR(response,"SUBSCRIBE")) &&
          (MSG_TEST_CODE(response, 202))) {
         DEBUGC(DBCLASS_PROXY, "proxy_request: Grandstream hack 202->404");
         response->status_code=404;
      }
}
      break;
   
  /*
   * from the internal masqueraded host to an external host
   */
   case RESTYP_OUTGOING:
      DEBUGC(DBCLASS_PROXY,"outgoing response for %s@%s from inbound",
	     response->from->url->username ?
                response->from->url->username : "*NULL*",
	     response->from->url->host ? 
                response->from->url->host : "*NULL*");

      /* rewrite Contact header to represent the masqued address */
      sip_rewrite_contact(ticket, DIR_OUTGOING);

      /* If an 200 OK or 183 Trying answer to an INVITE request,
       * rewrite body */
      if ((MSG_IS_RESPONSE_FOR(response,"INVITE")) &&
          ((MSG_TEST_CODE(response, 200)) || 
           (MSG_TEST_CODE(response, 183)))) {
         /* This is an outgoing response, therefore an outgoing stream */
         sts = proxy_rewrite_invitation_body(response, DIR_OUTGOING);
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
         port = SIP_PORT;
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

   sipsock_send(sendto_addr, port, ticket->protocol,
                buffer, strlen(buffer)); 
   osip_free (buffer);
   return STS_SUCCESS;
}


/*
 * PROXY_REWRITE_INVITATION_BODY
 *
 * rewrites the outgoing INVITATION request or response packet
 * 
 * RETURNS
 *	STS_SUCCESS on success
 *	STS_FAILURE on error
 */
int proxy_rewrite_invitation_body(osip_message_t *mymsg, int direction){
   osip_body_t *body;
   sdp_message_t  *sdp;
   struct in_addr map_addr, addr_sess, addr_media, outside_addr, inside_addr;
   int sts;
   char *bodybuff;
   char clen[8]; /* content length: probably never more than 7 digits !*/
   int map_port, msg_port;
   int media_stream_no;
   sdp_connection_t *sdp_conn;
   sdp_media_t *sdp_med;
   int rtp_direction=0;
   int have_c_media=0;

   if (configuration.rtp_proxy_enable == 0) return STS_SUCCESS;

   /*
    * get SDP structure
    */
   sts = osip_message_get_body(mymsg, 0, &body);
   if (sts != 0) {
      if ((MSG_IS_RESPONSE_FOR(mymsg,"INVITE")) &&
          (MSG_TEST_CODE(mymsg, 183))) {
         /* 183 Trying *MAY* contain SDP data */
         DEBUGC(DBCLASS_PROXY, "rewrite_invitation_body: "
                "no body found in message");
         return STS_SUCCESS;
      } else {
         /* INVITE request and 200 response *MUST* contain SDP data */
         ERROR("rewrite_invitation_body: no body found in message");
         return STS_FAILURE;
      }
   }

   sts = osip_body_to_str(body, &bodybuff);
   sts = sdp_message_init(&sdp);
   sts = sdp_message_parse (sdp, bodybuff);
   osip_free(bodybuff);
   if (sts != 0) {
      ERROR("rewrite_invitation_body: unable to sdp_message_parse body");
      sdp_message_free(sdp);
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

   /* get outbound address */
   if (get_ip_by_ifname(configuration.outbound_if, &outside_addr) != 
       STS_SUCCESS) {
      ERROR("can't find outbound interface %s - configuration error?",
            configuration.outbound_if);
      sdp_message_free(sdp);
      return STS_FAILURE;
   }

   /* get inbound address */
   if (get_ip_by_ifname(configuration.inbound_if, &inside_addr) !=
       STS_SUCCESS) {
      ERROR("can't find inbound interface %s - configuration error?",
             configuration.inbound_if);
      sdp_message_free(sdp);
       return STS_FAILURE;
    }

   /* figure out what address to use for RTP masquerading */
   if (MSG_IS_REQUEST(mymsg)) {
      if (direction == DIR_INCOMING) {
         map_addr = inside_addr;
         rtp_direction = DIR_OUTGOING;
      } else {
         map_addr = outside_addr;
         rtp_direction = DIR_INCOMING;
      }
   } else /* MSG_IS_REPONSE(mymsg) */ {
      if (direction == DIR_INCOMING) {
         map_addr = inside_addr;
         rtp_direction = DIR_OUTGOING;
      } else {
         map_addr = outside_addr;
         rtp_direction = DIR_INCOMING;
      }
   }


   /*
    * first, check presence of a 'c=' item on session level
    */
   if (sdp->c_connection==NULL || sdp->c_connection->c_addr==NULL) {
      /*
       * No 'c=' on session level, search on media level now
       *
       * According to RFC2327, ALL media description must
       * include a 'c=' item now:
       */
      media_stream_no=0;
      while (!sdp_message_endof_media(sdp, media_stream_no)) {
         /* check if n'th media stream is present */
         if (sdp_message_c_addr_get(sdp, media_stream_no, 0) == NULL) {
            ERROR("SDP: have no 'c=' on session level and neither "
                  "on media level (media=%i)",media_stream_no);
            sdp_message_free(sdp);
            return STS_FAILURE;
         }
         media_stream_no++;
      } /* while */
   }

   /* Required 'c=' items ARE present */


   /*
    * rewrite 'c=' item on session level if present and not yet done.
    * remember the original address in addr_sess
    */
   memset(&addr_sess, 0, sizeof(addr_sess));
   if (sdp->c_connection && sdp->c_connection->c_addr) {
      sts = get_ip_by_host(sdp->c_connection->c_addr, &addr_sess);
      if (sts == STS_FAILURE) {
         ERROR("SDP: cannot resolve session 'c=' host [%s]",
               sdp->c_connection->c_addr);
         sdp_message_free(sdp);
         return STS_FAILURE;
      }
      /*
       * Rewrite
       * an IP address of 0.0.0.0 means *MUTE*, don't rewrite such
       */
      /*&&&& should use gethostbyname here */
      if (strcmp(sdp->c_connection->c_addr, "0.0.0.0") != 0) {
         osip_free(sdp->c_connection->c_addr);
         sdp->c_connection->c_addr=osip_malloc(HOSTNAME_SIZE);
         sprintf(sdp->c_connection->c_addr, "%s", utils_inet_ntoa(map_addr));
      } else {
         /* 0.0.0.0 - don't rewrite */
         DEBUGC(DBCLASS_PROXY, "proxy_rewrite_invitation_body: "
                "got a MUTE c= record (on session level - legal?)");
      }
   }


   /*
    * rewrite 'o=' item (originator) on session level if present.
    */
   if (sdp->o_addrtype && sdp->o_addr) {
      if (strcmp(sdp->o_addrtype, "IP4") != 0) {
         ERROR("got IP6 in SDP originator - not yet suported by siproxd");
         sdp_message_free(sdp);
         return STS_FAILURE;
      }

      osip_free(sdp->o_addr);
      sdp->o_addr=osip_malloc(HOSTNAME_SIZE);
      sprintf(sdp->o_addr, "%s", utils_inet_ntoa(map_addr));
   }


   /*
    * loop through all media descritions,
    * start RTP proxy and rewrite them
    */
   for (media_stream_no=0;;media_stream_no++) {
      /* check if n'th media stream is present */
      if (sdp_message_m_port_get(sdp, media_stream_no) == NULL) break;

      /*
       * check if a 'c=' item is present in this media description,
       * if so -> rewrite it
       */
      memset(&addr_media, 0, sizeof(addr_media));
      have_c_media=0;
      sdp_conn=sdp_message_connection_get(sdp, media_stream_no, 0);
      if (sdp_conn && sdp_conn->c_addr) {
         /*&&&& should use gethostbyname here as well */
         if (strcmp(sdp_conn->c_addr, "0.0.0.0") != 0) {
            sts = get_ip_by_host(sdp_conn->c_addr, &addr_media);
            have_c_media=1;
            /* have a valid address */
            osip_free(sdp_conn->c_addr);
            sdp_conn->c_addr=osip_malloc(HOSTNAME_SIZE);
            sprintf(sdp_conn->c_addr, "%s", utils_inet_ntoa(map_addr));
         } else {
            /* 0.0.0.0 - don't rewrite */
            DEBUGC(DBCLASS_PROXY, "proxy_rewrite_invitation_body: got a "
                   "MUTE c= record (media level)");
         }
      }

      /* start an RTP proxying stream */
      if (sdp_message_m_port_get(sdp, media_stream_no)) {
         msg_port=atoi(sdp_message_m_port_get(sdp, media_stream_no));

         if (msg_port > 0) {
            osip_uri_t *cont_url = NULL;
            char *client_id=NULL;
            /* try to get some additional UA specific unique ID.
             * Try:
             * 1) User part of Contact header
             * 2) Host part of Contact header (will be different
             *    between internal UA and external UA)
             */
            if (!osip_list_eol(mymsg->contacts, 0))
               cont_url = ((osip_contact_t*)(mymsg->contacts->node->element))->url;
            if (cont_url) {
               client_id=cont_url->username;
               if (client_id == NULL) client_id=cont_url->host;
            }


            /*
             * do we have a 'c=' item on media level?
             * if not, use the same as on session level
             */
            if (have_c_media == 0) {
               memcpy(&addr_media, &addr_sess, sizeof(addr_sess));
            }

            sts = rtp_start_fwd(osip_message_get_call_id(mymsg),
                                client_id,
                                rtp_direction,
                                media_stream_no,
                                map_addr, &map_port,
                                addr_media, msg_port);

            if (sts == STS_SUCCESS) {
               /* and rewrite the port */
               sdp_med=osip_list_get(sdp->m_medias, media_stream_no);
               if (sdp_med && sdp_med->m_port) {
                  osip_free(sdp_med->m_port);
                  sdp_med->m_port=osip_malloc(8); /* 5 digits, \0 + align */
                  sprintf(sdp_med->m_port, "%i", map_port);
                  DEBUGC(DBCLASS_PROXY, "proxy_rewrite_invitation_body: "
                         "m= rewrote port to [%i]",map_port);
               } else {
                  ERROR("rewriting port in m= failed sdp_med=%p, "
                        "m_number_of_port=%p", sdp_med, sdp_med->m_port);
               }
            } /* sts == success */
         } /* if msg_port > 0 */
      } else {
         /* no port defined - skip entry */
         WARN("no port defined in m=(media) stream_no=%i", media_stream_no);
         continue;
      }
   } /* for media_stream_no */

   /* remove old body */
   sts = osip_list_remove(mymsg->bodies, 0);
   osip_body_free(body);

   /* dump new body */
   sdp_message_to_str(sdp, &bodybuff);

   /* free sdp structure */
   sdp_message_free(sdp);

   /* include new body */
   osip_message_set_body(mymsg, bodybuff);

   /* free content length resource and include new one*/
   osip_content_length_free(mymsg->content_length);
   mymsg->content_length=NULL;
   sprintf(clen,"%i",strlen(bodybuff));
   sts = osip_message_set_content_length(mymsg, clen);

   /* free old body */
   osip_free(bodybuff);

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
 * PROXY_REWRITE_REQUEST_URI
 *
 * rewrites the incoming Request URI
 * 
 * RETURNS
 *	STS_SUCCESS on success
 */
int proxy_rewrite_request_uri(osip_message_t *mymsg, int idx){
   char *host;
   char *port;
   osip_uri_t *url;

   if ((idx >= URLMAP_SIZE) || (idx < 0)) {
      WARN("proxy_rewrite_request_uri: called with invalid index");
      return STS_FAILURE;
   }

   DEBUGC(DBCLASS_PROXY,"rewriting incoming Request URI");
   url=osip_message_get_uri(mymsg);

   /* set the true host */
   if (url->host) osip_free(url->host);url->host=NULL;
   if (urlmap[idx].true_url->host) {
      DEBUGC(DBCLASS_BABBLE,"proxy_rewrite_request_uri: host=%s",
             urlmap[idx].true_url->host);
      host = (char *)malloc(strlen(urlmap[idx].true_url->host)+1);
      memcpy(host, urlmap[idx].true_url->host, strlen(urlmap[idx].true_url->host));
      host[strlen(urlmap[idx].true_url->host)]='\0';
      osip_uri_set_host(url, host);
   }

   /* set the true port */
   if (url->port) osip_free(url->port);url->port=NULL;
   if (urlmap[idx].true_url->port) {
      DEBUGC(DBCLASS_BABBLE,"proxy_rewrite_request_uri: port=%s",
             urlmap[idx].true_url->port);
      port = (char *)malloc(strlen(urlmap[idx].true_url->port)+1);
      memcpy(port, urlmap[idx].true_url->port, strlen(urlmap[idx].true_url->port));
      port[strlen(urlmap[idx].true_url->port)]='\0';
      osip_uri_set_port(url, port);
   }
   return STS_SUCCESS;
}

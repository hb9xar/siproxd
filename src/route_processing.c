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


/*
 * PROXY_PREPROCESS_ROUTE
 *
 * Route Information Preprocessing
 * 
 * RETURNS
 *	STS_SUCCESS on success
 */
int route_preprocess(sip_ticket_t *ticket){
   osip_message_t *mymsg=ticket->sipmsg;
   int sts;
   struct in_addr addr1, addr2, addr3;
   osip_route_t *route;
   int last;
   int i, j;
   /*
   The proxy MUST inspect the Request-URI of the request.  If the
   Request-URI of the request contains a value this proxy previously
   placed into a Record-Route header field (see Section 16.6 item 4),
   the proxy MUST replace the Request-URI in the request with the last
   value from the Route header field, and remove that value from the
   Route header field.  The proxy MUST then proceed as if it received
   this modified request.
   */

   /*
    * Check if I am listed at the topmost Route header (if any Route
    * header is existing at all). If so, remove it from the list and
    * rewrite the request URI to point to the now topmost Route.
    */
   if (mymsg->routes && (osip_list_size(mymsg->routes)>0)) {
      last=osip_list_size(mymsg->routes)-1;
      /*
       * I have seen that some (all?) UAs do set a Route: header
       * pointing to myself AT THE END OF THE LIST!
       * I don't really understand why, reading the Routing parts
       * of the RFC3261 did not help. All I know is, this last Route
       * header must be removed, otherwise any remote Proxy/Server
       * in the path will try to forward the packet to our private net.
       *
       * so the quick and dirty HACK is to check the topmost and
       * the last Route entry if it belongs to me...
       *
       * Any proper explanation to this is heavily welcome
       */
      for (j=0,i=last; j<2; j++, i=0) {
         DEBUGC(DBCLASS_PROXY, "route_preprocess: checking Route "
                "header[%i]", i);
         route = (osip_route_t *) osip_list_get(mymsg->routes, i);
         if (route == NULL) continue;
         if (route->url == NULL) continue;
         if (route->url->host == NULL) continue;

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
            osip_list_remove(mymsg->routes, i);
            osip_route_free(route);
            /* request->routes will be freed by osip_message_free() */
            DEBUGC(DBCLASS_PROXY, "removed Route header pointing to myself");
         }
      }
   }
   return STS_SUCCESS;
}


/*
 * PROXY_POSTPROCESS_ROUTE
 *
 * Route Information Postprocessing
 * 
 * RETURNS
 *	STS_SUCCESS on success
 */
int route_postprocess(sip_ticket_t *ticket){
   osip_message_t *mymsg=ticket->sipmsg;
   osip_uri_t *url;
   osip_route_t *route=NULL;
   osip_uri_param_t *param=NULL;

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
/* we are not a real proxy - and from the outside we look like an UA.
So we should not fiddle around with the Route headers.
We should use the first Route header to send the packet to
(RFC3261, section 8.1.2) */

   if (mymsg->routes && !osip_list_eol(mymsg->routes, 0)) {

      route = (osip_route_t *) osip_list_get(mymsg->routes, 0);
      if (route->url) {
         /* check for non existing lr parameter */
         if (osip_uri_uparam_get_byname(route->url, "lr", &param) != 0) {
            osip_route_t *new_route=NULL;
            url=osip_message_get_uri(mymsg);

            /* push Request URI into Route header list at the last position */
            osip_route_init(&new_route);
            osip_uri_clone(url, &new_route->url);
            osip_list_add(mymsg->routes, new_route, -1);

            /* rewrite request URI to now topmost Route header */
            DEBUGC(DBCLASS_PROXY, "Route header w/o 'lr': rewriting request "
                   "URI from %s to %s", url->host, route->url->host);
            osip_uri_free(url);
            url=NULL;
            osip_uri_clone(route->url, &url);
            /* remove first Route header from list & free */
            osip_list_remove(mymsg->routes, 0);
            osip_route_free(route);
            route = NULL;
         }
      }
   }
   return STS_SUCCESS;
}


/*
 * PROXY_ADD_RECORDROUTE
 *
 * Add a Record-route header
 * 
 * RETURNS
 *	STS_SUCCESS on success
 */
int route_add_recordroute(sip_ticket_t *ticket){
   osip_message_t *mymsg=ticket->sipmsg;
   int sts;
   struct in_addr addr;
   osip_record_route_t *r_route;
   osip_uri_t *uri_of_proxy;

   /*
    * RFC 3261, Section 16.6 step 4
    * Proxy Behavior - Request Forwarding - Add a Record-route header
    */

   /*
    * get the IP address of the interface where I'm going to
    * send out this request
    */
   switch (ticket->direction) {
   case REQTYP_INCOMING:
   case RESTYP_INCOMING:
      if (get_ip_by_ifname(configuration.inbound_if, &addr) != STS_SUCCESS) {
         ERROR("can't find inbound interface %s - configuration error?",
               configuration.inbound_if);
         return STS_FAILURE;
      }
      break;
   case REQTYP_OUTGOING:
   case RESTYP_OUTGOING:
      if (get_ip_by_ifname(configuration.outbound_if, &addr) != STS_SUCCESS) {
         ERROR("can't find outbound interface %s - configuration error?",
               configuration.outbound_if);
         return STS_FAILURE;
      }
      break;
   default:
      ERROR("Oops, never should end up here (direction=%i)", ticket->direction);
      return STS_FAILURE;
   }

   sts = osip_record_route_init(&r_route);
   if (sts == 0) {
      sts = osip_uri_init(&uri_of_proxy);
      if (sts == 0) {
         char tmp[8];

         /* host name / IP */
         osip_uri_set_host(uri_of_proxy, osip_strdup(utils_inet_ntoa(addr)));
         osip_uri_set_username(uri_of_proxy, osip_strdup("siproxd"));

         /* port number */
         sprintf(tmp, "%i", configuration.sip_listen_port);
         osip_uri_set_port(uri_of_proxy, osip_strdup(tmp));

         /* 'lr' parameter */
         osip_uri_uparam_add(uri_of_proxy, "lr", NULL);

         osip_record_route_set_url(r_route, uri_of_proxy);

         /* insert before all other record-route */
         osip_list_add (mymsg->record_routes, r_route, 0);
      } else {
          osip_record_route_free(r_route);
      } /* if url_init */
   } /* if record route init */


   return STS_SUCCESS;
}


/*
 * PROXY_PURGE_RECORDROUTE
 *
 * Purge all Record-route headers
 * 
 * RETURNS
 *	STS_SUCCESS on success
 */
int route_purge_recordroute(sip_ticket_t *ticket){
   osip_message_t *mymsg=ticket->sipmsg;
   osip_record_route_t *r_route=NULL;

   if (mymsg->record_routes && !osip_list_eol(mymsg->record_routes, 0)) {
      while (!osip_list_eol(mymsg->record_routes, 0)) {
      r_route = (osip_record_route_t *) osip_list_get(mymsg->record_routes, 0);
      osip_list_remove(mymsg->record_routes, 0);
      osip_record_route_free(r_route);
      /* mymsg->record_routes will be freed by osip_message_free() */
      }
   }
   return STS_SUCCESS;
}


/*
 * PROXY_DETERMINE_NEXT_HOP
 *
 * check if a route-header exists and give back the next hop
 * 
 * RETURNS
 *	STS_SUCCESS on success
 */
int route_determine_nexthop(sip_ticket_t *ticket,
                            struct in_addr *dest, int *port){
   int sts;
   osip_message_t *mymsg=ticket->sipmsg;
   osip_route_t *route=NULL;

   /*
   * Check for existing route header. If so, the topmost will be
   * the next hop.
   *
   * If this route header does NOT have a lr parameter set, rewrite
   * the SIP URI to point to the destination of the route (NOT IMPLEMENTED)
   */
   if (mymsg->routes && !osip_list_eol(mymsg->routes, 0)) {

      /* get the destination from the Route Header */
      route = (osip_route_t *) osip_list_get(mymsg->routes, 0);
      if (route==NULL || route->url==NULL || route->url->host==NULL) {
         DEBUGC(DBCLASS_PROXY, "route_determine_nexthop: got broken Route "
                "header - discarding packet");
         return STS_FAILURE;
      }

      sts = get_ip_by_host(route->url->host, dest);
      if (sts == STS_FAILURE) {
         DEBUGC(DBCLASS_PROXY, "route_determine_nexthop: cannot resolve "
                "Route URI [%s]", route->url->host);
         return STS_FAILURE;
      }

      if (route->url->port) {
         *port=atoi(route->url->port);
      } else {
         *port=SIP_PORT;
      }

      osip_list_remove(mymsg->routes, 0);
      osip_route_free(route);
      /* request->routes will be freed by osip_message_free() */
   }

   return STS_SUCCESS;
}

/* -*- Mode: C; c-basic-offset: 3 -*-
    Copyright (C) 2002-2005  Thomas Ries <tries@gmx.net>

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
//#include <errno.h>
#include <string.h>
//#include <stdlib.h>
//#include <unistd.h>
//#include <signal.h>
#include <netinet/in.h>
//#include <arpa/inet.h>

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
//#include "plugins.h"
#include "log.h"

static char const ident[]="$Id$";

/* configuration storage */
extern struct siproxd_config configuration;



/* local prototypes */
static int plugin_shortdial_process(sip_ticket_t *ticket);


/* code (entry point) */
int plugin_shortdial(sip_ticket_t *ticket) {

   DEBUGC(DBCLASS_PLUGIN,"plugin entered");

   /* only deal with outoing calls (outgoing INVITE requests) */
   sip_find_direction(ticket, NULL);
   if ((ticket->direction == DIR_OUTGOING) ||
       (MSG_IS_INVITE(ticket->sipmsg))) {
      /* To header with username must exist, max of 2 characters */
      if (ticket && ticket->sipmsg && ticket->sipmsg && 
          ticket->sipmsg->to && ticket->sipmsg->to->url &&
          ticket->sipmsg->to->url->username &&
          (strlen(ticket->sipmsg->to->url->username) >= 2) &&
          configuration.pi_shortdial_akey) {
         char digit1=ticket->sipmsg->to->url->username[0];
         /* check for "activation key" - 1st character in number dialled */
         if (digit1 == configuration.pi_shortdial_akey[0]) {
            DEBUGC(DBCLASS_PLUGIN,"processing");
            plugin_shortdial_process(ticket);
         }
      }
   }

   DEBUGC(DBCLASS_PLUGIN,"plugin left");
   return STS_SUCCESS;
}


/* private code */
static int plugin_shortdial_process(sip_ticket_t *ticket) {
   osip_uri_t *to_url=ticket->sipmsg->to->url;
   osip_uri_t *req_url;
   char *to_user=to_url->username;
   char *new_to_user=NULL;
   int  shortcut_no=0;
   int  i, len;

   DEBUGC(DBCLASS_PLUGIN,"process: username=[%s]", to_user);

   req_url=osip_message_get_uri(ticket->sipmsg);

   /* escaped akey? (if it appears twice: e.g. "**1234" -> "*1234") */
   if (to_user[1] == configuration.pi_shortdial_akey[0]) {
      /* shift left the whole string for 1 position (incl \0 termination)*/
      for (i=0; i<strlen(to_user); i++) {
         to_user[i]=to_user[i+1];
      }
      return STS_SUCCESS;
   }

   /* extract number */
   shortcut_no = atoi(&(to_user[1]));
   if (shortcut_no <= 0) return STS_SUCCESS; /* not a number */

   /* requested number is not defined */
   if (shortcut_no > configuration.pi_shortdial_entry.used) {
      INFO ("shortdial: requested shortcut %i > available shortcuts",
            shortcut_no, configuration.pi_shortdial_entry.used);
      return STS_SUCCESS;
   }

   /* actual replacement INVITE and To header */
   new_to_user=configuration.pi_shortdial_entry.string[shortcut_no-1];
   if (new_to_user) {
      DEBUGC(DBCLASS_PLUGIN,"process: rewriting [%s]->[%s]",
             to_user, new_to_user);
      len=strlen(new_to_user)+1; /* include trailing "\0" */

      /* Request URI */
      if (req_url && req_url->username) {
         osip_free(req_url->username);
         req_url->username=osip_malloc(len);
         strncpy(req_url->username, new_to_user, len);
      }

      /* To header */
      to_user=NULL;
      osip_free(to_url->username);
      to_url->username=osip_malloc(len);
      strncpy(to_url->username, new_to_user, len);
   }

   /* done */
   return STS_SUCCESS;
}

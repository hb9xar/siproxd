/*
    Copyright (C) 2002-2008  Thomas Ries <tries@gmx.net>

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
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "log.h"
#include "plugins.h"

static char const ident[]="$Id$";

/* configuration storage */
extern struct siproxd_config configuration;

/* local prototypes */
static int plugin_shortdial_redirect(sip_ticket_t *ticket, int shortcut_no);
static int plugin_shortdial(sip_ticket_t *ticket);



/* 
 * Plugin API functions code
 */
/* Initialization */
int  plugin_init(plugin_def_t *plugin_def) {
   plugin_def->api_version=SIPROXD_API_VERSION;
   plugin_def->name=strdup("plugin_shortdial");
   plugin_def->desc=strdup("Handles Dial shortcuts as defined in config file");
   plugin_def->exe_mask=PLUGIN_DETERMINE_TARGET;
   return STS_SUCCESS;
}

/* Processing */
int  plugin_process(int stage, sip_ticket_t *ticket){
   int sts;
   sts=plugin_shortdial(ticket);
   return sts;
}

/* De-Initialization */
int  plugin_end(plugin_def_t *plugin_def){
   /* free my allocated rescources */
   if (plugin_def->name) {free(plugin_def->name); plugin_def->name=NULL;}
   if (plugin_def->desc) {free(plugin_def->desc); plugin_def->desc=NULL;}

   return STS_SUCCESS;
}


/*
 * Workload code
 */

/* returns STS_SIP_SENT if processing is to be terminated,
 * otherwise STS_SUCCESS (go on with processing) */
/* code (entry point) */
static int plugin_shortdial(sip_ticket_t *ticket) {
   int sts=STS_SUCCESS;
   osip_uri_t *req_url;
   int  shortcut_no=0;

   /* plugin loaded and not configured, return with success */
   if (configuration.pi_shortdial_akey==NULL) return STS_SUCCESS;
   if (configuration.pi_shortdial_entry.used==0) return STS_SUCCESS;

   DEBUGC(DBCLASS_PLUGIN,"plugin entered");
   req_url=osip_message_get_uri(ticket->sipmsg);

   /* only outgoing direction is handled */
   sip_find_direction(ticket, NULL);
   if (ticket->direction != DIR_OUTGOING)
      return STS_SUCCESS;

   /* only INVITE and ACK are handled */
   if (!MSG_IS_INVITE(ticket->sipmsg) && !MSG_IS_ACK(ticket->sipmsg))
      return STS_SUCCESS;

   /* REQ URI with username must exist, length as defined in config,
    * shortdial must be enabled and short dial key must match */
   if (!req_url || !req_url->username ||
       !configuration.pi_shortdial_akey ||
       (strlen(req_url->username) != strlen(configuration.pi_shortdial_akey)) ||
       (req_url->username[0] != configuration.pi_shortdial_akey[0]))
      return STS_SUCCESS; /* ignore */

   shortcut_no = atoi(&(req_url->username[1]));
   if ((shortcut_no <= 0) || (shortcut_no >= LONG_MAX)) return STS_SUCCESS; /* not a number */

   /* requested number is not defined (out of range) */
   if (shortcut_no > configuration.pi_shortdial_entry.used) {
      DEBUGC(DBCLASS_PLUGIN, "shortdial: shortcut %i > available shortcuts (%i)",
            shortcut_no, configuration.pi_shortdial_entry.used);
      return STS_SUCCESS;
   }

   /* requested number is not defined (empty) */
   if (!configuration.pi_shortdial_entry.string[shortcut_no-1]) {
      DEBUGC(DBCLASS_PLUGIN, "shortdial: shortcut %i empty", shortcut_no);
      return STS_SUCCESS;
   }

   /*
    * called number does match the short dial specification
    */

   /* outgoing INVITE request */
   if (MSG_IS_INVITE(ticket->sipmsg)) {
      DEBUGC(DBCLASS_PLUGIN,"processing INVITE");
      sts=plugin_shortdial_redirect(ticket, shortcut_no);
   }
   /* outgoing ACK request: is result of a local 3xx answer (moved...) */
   else if (MSG_IS_ACK(ticket->sipmsg)) {
      /* make sure we only catch ACKs caused by myself (**02 -> *02 legitime) */
      DEBUGC(DBCLASS_PLUGIN,"processing ACK");
      sts=STS_SIP_SENT; /* eat up the ACK that was directed to myself */
   }

   return sts;
}


/* private plugin code */
static int plugin_shortdial_redirect(sip_ticket_t *ticket, int shortcut_no) {
   osip_uri_t *to_url=ticket->sipmsg->to->url;
   char *to_user=to_url->username;
   char *new_to_user=NULL;
   int  i;
   size_t len;
   osip_contact_t *contact = NULL;

   new_to_user=configuration.pi_shortdial_entry.string[shortcut_no-1];
   if (!new_to_user) return STS_SUCCESS;

   DEBUGC(DBCLASS_PLUGIN,"redirect: redirecting [%s]->[%s]",
          to_user, new_to_user);
   len=strlen(new_to_user)+1; /* include trailing "\0" */

   /* use a "302 Moved temporarily" response back to the client */
   /* new target is within the Contact Header */

   /* remove all Contact headers in message */
   for (i=0; (contact != NULL) || (i == 0); i++) {
      osip_message_get_contact(ticket->sipmsg, 0, &contact);
      if (contact) {
         osip_list_remove(&(ticket->sipmsg->contacts),0);
         osip_contact_free(contact);
      }
   } /* for i */

   /* insert one new Contact header containing the new target address */
   osip_contact_init(&contact);
   osip_uri_clone(to_url, &contact->url);
   osip_free(contact->url->username);
   contact->url->username=osip_malloc(len);
   strcpy(contact->url->username, new_to_user);

   osip_list_add(&(ticket->sipmsg->contacts),contact,0);

   /* sent redirect message back to local client */
   sip_gen_response(ticket, 302 /*Moved temporarily*/);

   return STS_SIP_SENT;
}

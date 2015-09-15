/*
    Copyright (C) 2015  Thomas Ries <tries@gmx.net>

    This file is part of Siproxd.

    Siproxd is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Siproxd is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warrantry of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Siproxd; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
*/

/* must be defined before including <plugin.h> */
#define PLUGIN_NAME	plugin_siptrunk

#include "config.h"

#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "plugins.h"
#include "log.h"

static char const ident[]="$Id$";

/* Plug-in identification */
static char name[]="plugin_siptrunk";
static char desc[]="Handles SIP trunks with multiple numbers on same SIP account";

/* global configuration storage - required for config file location */
extern struct siproxd_config configuration;

/* plugin configuration storage */
static struct plugin_config {
   stringa_t trunk_name;
   stringa_t trunk_account;
   stringa_t trunk_numbers;
} plugin_cfg;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
   { "plugin_siptrunk_name",     TYP_STRINGA,&plugin_cfg.trunk_name,	{0, NULL} },
   { "plugin_siptrunk_account",  TYP_STRINGA,&plugin_cfg.trunk_account,	{0, NULL} },
   { "plugin_siptrunk_numbers",  TYP_STRINGA,&plugin_cfg.trunk_numbers,	{0, NULL} },
   {0, 0, 0}
};

/* Prototypes */
static int sip_fix_topvia(sip_ticket_t *ticket);

/*&&&+++
1) register
  - nothing to to
2) outgoing calls
  - nothing to do. Should be able to figure out direction by
    Contact header, via header
3) incoming call
  * need matching of incoming DID number to trunk account
    - SIP URI
    - To: Header
  How do I pass on that matched information?
  ? rewriting To: header?
  ? rewriting SIP URI?
  ? new metadata in ticket structure?
Need to provide info for sip_find_direction() -nope, this has been processed
(and failed) before the plugin. I need to provide the correct drection value in
the ticket.
Then with an Route header I may set the next Hop (to the internal UA). I need to
access the registration database to get the associated IP address with the
account...
Unfortunately, the route header processing is only done for OUTGOING requests.

Probably should try with rewritung the SIP URI to the account name. However this
is bad bcoz if destroys the DID number information in the request URI.

I may need some next hop override that a plugin can use to force the next hop,
no matter what...


&&&---*/

/* 
 * Initialization.
 * Called once suring siproxd startup.
 */
int  PLUGIN_INIT(plugin_def_t *plugin_def) {
   /* API version number of siproxd that this plugin is built against.
    * This constant will change whenever changes to the API are made
    * that require adaptions in the plugin. */
   plugin_def->api_version=SIPROXD_API_VERSION;

   /* Name and descriptive text of the plugin */
   plugin_def->name=name;
   plugin_def->desc=desc;

   /* Execution mask - during what stages of SIP processing shall
    * the plugin be called. */
   plugin_def->exe_mask=PLUGIN_PRE_PROXY;

   /* read the config file */
   if (read_config(configuration.configfile,
                   configuration.config_search,
                   plugin_cfg_opts, name) == STS_FAILURE) {
      ERROR("Plugin '%s': could not load config file", name);
      return STS_FAILURE;
   }

   INFO("plugin_siptrunk is initialized");
   return STS_SUCCESS;
}

/*
 * Processing.
 * 
 */
int  PLUGIN_PROCESS(int stage, sip_ticket_t *ticket){
   /* stage contains the PLUGIN_* value - the stage of SIP processing. */
   int type;
   osip_via_t *via;
   struct sockaddr_in from;

   type = ticket->direction;

DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: type=%i", type);

   /* Incoming SIP response? */
   if (type == RESTYP_INCOMING) {
      /* a Via header needs to be present in response */
      if((via = osip_list_get(&(ticket->sipmsg->vias), 0)) == NULL) {
         WARN("no Via header found in incoming SIP message");
         return STS_SUCCESS;
      }

      /* check for Via IP in configured range */
      DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: processing VIA host [%s]",
             via->host);
      get_ip_by_host(via->host, &(from.sin_addr));
      if ((plugin_cfg.networks != NULL) &&
          (strcmp(plugin_cfg.networks, "") !=0) &&
          (process_aclist(plugin_cfg.networks, ticket->from) == STS_SUCCESS) &&
          (process_aclist(plugin_cfg.networks, from) == STS_SUCCESS)) {

         /* VIA & Sender IP are in list, fix Via header */
         DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: replacing a bogus via");

         if (sip_fix_topvia(ticket) == STS_FAILURE) {
            ERROR("patching inbound Via failed!");
         }
      } else {
         DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: not match, returning.");
      }
      DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: done");
  }
   return STS_SUCCESS;
}

/*
 * De-Initialization.
 * Called during shutdown of siproxd. Gives the plugin the chance
 * to clean up its mess (e.g. dynamic memory allocation, database
 * connections, whatever the plugin messes around with)
 */
int  PLUGIN_END(plugin_def_t *plugin_def){
   INFO("plugin_siptrunk ends here");
   return STS_SUCCESS;
}

/*--------------------------------------------------------------------*/
static int sip_fix_topvia(sip_ticket_t *ticket) {
   osip_via_t *via;
   int sts;

   if((via = osip_list_get(&(ticket->sipmsg->vias), 0)) != NULL) {
      /* 1) IP of Via has been checked beforehand. */

      /* 2) remove broken via header */
      DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: removing topmost via");
      sts = osip_list_remove(&(ticket->sipmsg->vias), 0);
      osip_via_free (via);
      via = NULL;

      /* 3) add my via header */
      DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: adding new via");
      if (ticket->direction == RESTYP_INCOMING) {
         sts = sip_add_myvia(ticket, IF_OUTBOUND);
         if (sts == STS_FAILURE) {
            ERROR("adding my outbound via failed!");
         }
      } else {
         sts = sip_add_myvia(ticket, IF_INBOUND);
         if (sts == STS_FAILURE) {
            ERROR("adding my inbound via failed!");
         }
      }
   }

   return STS_SUCCESS;
}


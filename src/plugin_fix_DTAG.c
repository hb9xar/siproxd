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
#define PLUGIN_NAME	plugin_fix_DTAG

#include "config.h"

#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "plugins.h"
#include "log.h"

static char const ident[]="$Id: plugin_DTAG.c 439 2010-01-07 11:29:00Z hb9xar $";

/* Plug-in identification */
static char name[]="plugin_fix_DTAG";
static char desc[]="Fixes issues with DTAG (t-online.de) broken SIP headers";

/* global configuration storage - required for config file location */
extern struct siproxd_config configuration;

/* plugin configuration storage */
static struct plugin_config {
   char *networks;
} plugin_cfg;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
   { "plugin_fix_DTAG_networks",      TYP_STRING, &plugin_cfg.networks,	{0, NULL} },
   {0, 0, 0}
};

/* Prototypes */
static int sip_patch_topvia(sip_ticket_t *ticket);


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

   INFO("plugin_fix_DTAG is initialized");
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

   /* Incoming SIP response? */
DEBUGC(DBCLASS_PLUGIN, "plugin_fix_DTAG: type=%i", type);
   if (type == RESTYP_INCOMING) {

      if((via = osip_list_get(&(ticket->sipmsg->vias), 0)) == NULL) {
         WARN("no Via header found in incoming SIP message");
         return STS_SUCCESS;
      }

      get_ip_by_host(via->host, &(from.sin_addr));

      /* check for Via IP in configured range */
      if ((plugin_cfg.networks != NULL) &&
          (strcmp(plugin_cfg.networks, "") !=0) &&
          (process_aclist(plugin_cfg.networks, from) == STS_SUCCESS)) {
         /* is in list, patch Via header */
         DEBUGC(DBCLASS_PLUGIN, "plugin_fix_DTAG: replacing a bogus via");
         if (sip_patch_topvia(ticket) == STS_FAILURE) {
            ERROR("patching inbound Via failed!");
         }
      }
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
   INFO("plugin_fix_DTAG ends here");
   return STS_SUCCESS;
}

/*--------------------------------------------------------------------*/
static int sip_patch_topvia(sip_ticket_t *ticket) {
   osip_via_t *via;
   int sts;

   if((via = osip_list_get(&(ticket->sipmsg->vias), 0)) != NULL) {
      // 1) check that via header matches criteria (is not local)
      if (! is_via_local(via)) {
         // 2) remove broken via header
         sts = osip_list_remove(&(ticket->sipmsg->vias), 0);
         osip_via_free (via);
         via = NULL;

         // 3) add my via header
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
   }

   return STS_SUCCESS;
}


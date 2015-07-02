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
#define PLUGIN_NAME	plugin_stripheader

#include "config.h"

#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osipparser2/osip_parser.h>
#include <osipparser2/sdp_message.h>

#include "siproxd.h"
#include "plugins.h"
#include "log.h"

static char const ident[]="$Id$";

/* Plug-in identification */
static char name[]="plugin_stripheader";
static char desc[]="Allows removing SIP headers";

/* global configuration storage - required for config file location */
extern struct siproxd_config configuration;

/* plugin configuration storage */
static struct plugin_config {
   stringa_t header_remove;
} plugin_cfg;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
   { "plugin_stripheader_remove",      TYP_STRINGA, &plugin_cfg.header_remove,	{0, NULL} },
   {0, 0, 0}
};

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

   INFO("%s is initialized", name);
   return STS_SUCCESS;
}

/*
 * Processing.
 * 
 */
int  PLUGIN_PROCESS(int stage, sip_ticket_t *ticket){
   /* stage contains the PLUGIN_* value - the stage of SIP processing. */
   int i;
   int pos;
   char *header_remove=NULL;
   char *header_remove_args=NULL;
   int dlc=65535; /* deadlock counter... - just a life insurance */



   for (i=0; i<plugin_cfg.header_remove.used; i++) {
      DEBUGC(DBCLASS_PLUGIN, "%s: looking for header [%s], entry=%i", name, 
             plugin_cfg.header_remove.string[i], i);
      if (strchr(plugin_cfg.header_remove.string[i],':')) {
          int len=strchr(plugin_cfg.header_remove.string[i],':') - plugin_cfg.header_remove.string[i];
          header_remove = strndup(plugin_cfg.header_remove.string[i], len);
          header_remove_args = strdup(strchr(plugin_cfg.header_remove.string[i],':')+1);
     } else {
          header_remove = strdup(plugin_cfg.header_remove.string[i]);
      }


      /* special case Allow header */
      if (strcasecmp(header_remove, "allow") == 0) {
         osip_allow_t *allow=NULL;
         pos=0;
         while ((pos = osip_message_get_allow(ticket->sipmsg, 
                       pos, &allow)) != -1) {
             if (--dlc <= 0) { ERROR("deadlock counter has triggered. Likely a bug in code."); return STS_FAILURE;}
             if (header_remove_args == NULL) {
                /* remova all values for header */
                DEBUGC(DBCLASS_PLUGIN, "%s: removing Allow header pos=%i, val=%s", name, 
                       pos, allow->value);
                osip_list_remove(&ticket->sipmsg->allows, pos);
                osip_allow_free(allow);
                allow=NULL;
             } else {
                /* remove only values "header_remove_args" */
                if (osip_strcasecmp(header_remove_args, allow->value) == 0) {
                   DEBUGC(DBCLASS_PLUGIN, "%s: removing Allow header value pos=%i, val=%s", name, 
                          pos, allow->value);
                   osip_list_remove(&ticket->sipmsg->allows, pos);
                   osip_allow_free(allow);
                   allow=NULL;
                } else {
                   pos++;
                }
             }
          }

      /* generic headers */
      } else {
         osip_header_t *h=NULL;
         pos=0;
         while ((pos = osip_message_header_get_byname(ticket->sipmsg, 
                   header_remove, pos, &h)) != -1) {
             if (--dlc <= 0) { ERROR("deadlock counter has triggered. Likely a bug in code."); return STS_FAILURE;}
             if (header_remove_args == NULL) {
                /* remova all values for header */
                DEBUGC(DBCLASS_PLUGIN, "%s: removing header pos=%i, name=%s, val=%s", name, 
                       pos, h->hname, h->hvalue);
                osip_list_remove(&ticket->sipmsg->headers, pos);
                osip_header_free(h);
             } else {
                /* remove only values "header_remove_args" */
                if (osip_strcasecmp(header_remove_args, h->hvalue) == 0) {
                   DEBUGC(DBCLASS_PLUGIN, "%s: removing header value pos=%i, name=%s, val=%s", name, 
                          pos, h->hname, h->hvalue);
                   osip_list_remove(&ticket->sipmsg->headers, pos);
                   osip_header_free(h);
                   h=NULL;
                } else {
                   pos++;
                }
             } // if header_remove_args
         }
      }

      /* free resources */
      if (header_remove_args) {
         free (header_remove_args);
         header_remove_args = NULL;
      }
      if (header_remove) {
         free (header_remove);
         header_remove = NULL;
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
   INFO("%s ends here", name);
   return STS_SUCCESS;
}

/*
    Copyright (C) 2016  Thomas Ries <tries@gmx.net>

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
#define PLUGIN_NAME	plugin_fix_fbox_anoncall

#include "config.h"

#include <stdlib.h>
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
static char name[]="plugin_fix_fbox_anoncall";
static char desc[]="Fixes issues with incoming anonymous calls on Fritzbox UAs";

/* global configuration storage - required for config file location */
extern struct siproxd_config configuration;

/* global URL mapping table */
extern struct urlmap_s urlmap[];

/* plugin configuration storage */
static struct plugin_config {
   char *networks;	// networks where we shall fix Fritzbox behaviour
} plugin_cfg;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
   { "plugin_fix_fbox_anoncall_networks",      TYP_STRING, &plugin_cfg.networks,	{0, NULL} },
   {0, 0, 0}
};

/* Prototypes */
//static int sip_fix_topvia(sip_ticket_t *ticket);


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

   INFO("plugin_fix_fbox_anoncall is initialized");
   return STS_SUCCESS;
}

/*
 * Processing.
 * 
 */
int  PLUGIN_PROCESS(int stage, sip_ticket_t *ticket){
   /* stage contains the PLUGIN_* value - the stage of SIP processing. */
   int type;
   osip_contact_t *contact;
   int idx=0;
   int param_match_idx=0;
   int user_match=0;
   int param_match=0;
   char *tmp=NULL;

   type = ticket->direction;

   DEBUGC(DBCLASS_PLUGIN, "PLUGIN_PROCESS entered: type=%i", type);

   /* Outgoing SIP response? - may also need to process outgoing SIP requests - */
   if ((type == RESTYP_OUTGOING) || (type == REQTYP_OUTGOING)) {
      /* a Contact header needs to be present in response */
      osip_message_get_contact(ticket->sipmsg, 0, &contact);
      if(contact == NULL) {
         DEBUGC(DBCLASS_PLUGIN, "no Contact header found in SIP message");
         return STS_SUCCESS;
      }
      if(contact->url == NULL) {
         DEBUGC(DBCLASS_PLUGIN, "no Contact->url header found in SIP message");
         return STS_SUCCESS;
      }
      if (contact->url->host == NULL) {
         DEBUGC(DBCLASS_PLUGIN, "no Contact->url->host header found in SIP message");
         return STS_SUCCESS;
      }


/* 
   loop through URLMAP table
     compare IP, param, if match
       set partial match
       compare username, if match
         all OK with this Contact header, return from plugin
       if no math
         probably broken username part in header (as rest matches)
         remember urlmap index
   end loop
   if partial match == 0
     unable to figure out how to fix contact header.
     dump some info
   if partial match == 1
     replace username part from urlmap[saved_index].true_url
   return from plugin

*/

      /* check for sender IP is in configured range */
      DEBUGC(DBCLASS_PLUGIN, "processing from host [%s]",
             utils_inet_ntoa(ticket->from.sin_addr));
      if ((plugin_cfg.networks != NULL) &&
          (strcmp(plugin_cfg.networks, "") !=0) &&
          (process_aclist(plugin_cfg.networks, ticket->from) == STS_SUCCESS)) {
         /* Sender IP is in list, fix check and fix Contact header */
         DEBUGC(DBCLASS_PLUGIN, "checking for bogus Contact header");

         /* loop through urlmap table */
         for (idx=0; idx<URLMAP_SIZE; idx++){
            if (urlmap[idx].active == 0) continue;
            if (urlmap[idx].true_url == NULL) continue;

            /* outgoing response - only look for true_url */
            /* 1) check host, skip of no match */
            if (contact->url->host && urlmap[idx].true_url->host) {
               if (osip_strcasecmp(contact->url->host, urlmap[idx].true_url->host) != 0) { 
                  /* no IP match, continue */
                  continue;
               }
            }
            DEBUGC(DBCLASS_PLUGIN, "idx=%i, IP/Host match [%s]", 
                   idx, contact->url->host);
            osip_uri_to_str(contact->url, &tmp); \
            DEBUGC(DBCLASS_PLUGIN, "   contact->url=[%s]", (tmp)? tmp: "NULL");
            if (tmp) osip_free(tmp);
            tmp = NULL;
            osip_uri_to_str(urlmap[idx].true_url, &tmp); \
            DEBUGC(DBCLASS_PLUGIN, "   urlmap[%i]->true_url=[%s]", idx, (tmp)? tmp: "NULL");
            if (tmp) osip_free(tmp);
            tmp = NULL;

            /* 2) check username match */
            if (contact->url->username && urlmap[idx].true_url->username) {
               DEBUGC(DBCLASS_PLUGIN, "check username: "
                      "contact->url->username [%s] <-> true_url->username [%s]",
                      contact->url->username, urlmap[idx].true_url->username);
              if (osip_strcasecmp(contact->url->username, urlmap[idx].true_url->username) == 0) {
                 /* MATCH, all OK - return */
                 user_match=1;
                 DEBUGC(DBCLASS_PLUGIN, "username matches");
                 break;
              }
            } else {
               DEBUGC(DBCLASS_PLUGIN, "NULL username: "
                      "contact->username 0x%p <-> true_url->username 0x%p",
                      contact->url->username, urlmap[idx].true_url->username);
            }

            /* 3) check param field ("uniq=" param)*/
            {
               int sts1, sts2;
               osip_uri_param_t *p1=NULL, *p2=NULL;

               sts1=osip_uri_param_get_byname(&(contact->url->url_params), "uniq", &p1);
               sts2=osip_uri_param_get_byname(&(urlmap[idx].true_url->url_params), "uniq", &p2);
               if ( ((sts1 == OSIP_SUCCESS) && (sts2 == OSIP_SUCCESS)) &&
                     (p1 && p2) &&
                     (p1->gname && p2->gname && p1->gvalue && p2->gvalue) ) {
                  DEBUGC(DBCLASS_PLUGIN, "check param: "
                         "contact-> [%s]=[%s] <-> true_url->[%s]=[%s]",
                         p1->gname, p1->gvalue, p2->gname, p2->gvalue);

                  if ((osip_strcasecmp(p1->gname, p2->gname) == 0) &&
                        (osip_strcasecmp(p1->gvalue, p2->gvalue) == 0) ) {
                     /* MATCH */
                     param_match=1;
                     param_match_idx=idx;
                     DEBUGC(DBCLASS_PLUGIN, "uniq param matches");
                  }
               } else {
                  if (p1 && p2) {
                  DEBUGC(DBCLASS_PLUGIN, "NULL 'uniq' param fields: "
                         "contact-> 0x%p=0x%p <-> true_url->0x%p=0x%p",
                         p1->gname, p1->gvalue, p2->gname, p2->gvalue);
                  } else {
                  DEBUGC(DBCLASS_PLUGIN, "NULL 'uniq' param: "
                         "contact->param 0x%p <-> true_url->param 0x%p",
                         p1, p2);
                  }
               }
            }
               
         } // for

         /* full match (host & user) */
         if (user_match == 1) {
            DEBUGC(DBCLASS_PLUGIN, "PLUGIN_PROCESS exit: got a user@host match - OK");
            return STS_SUCCESS;
         }

         /* no partial match (no host, or no user / no param match) */
         if (param_match == 0) {
            DEBUGC(DBCLASS_PLUGIN, "PLUGIN_PROCESS exit: bogus outgoing response Contact header from [%s], "
                   "unable to sanitize!", utils_inet_ntoa(ticket->from.sin_addr));
            return STS_SUCCESS;
         }

         /* param_match - replace the username part from [param_match_idx] -> Contact */
         /* replace contact URI (username part) */
         osip_free(contact->url->username);
         osip_uri_set_username(contact->url, 
                               osip_strdup(urlmap[param_match_idx].true_url->username));

         DEBUGC(DBCLASS_PLUGIN, "sanitized Contact from [%s]",
                utils_inet_ntoa(ticket->from.sin_addr));


      } else {
         DEBUGC(DBCLASS_PLUGIN, "no aclist IP match, returning.");
      }
   } // if (type == ..
   DEBUGC(DBCLASS_PLUGIN, "PLUGIN_PROCESS exit");
   return STS_SUCCESS;
}

/*
 * De-Initialization.
 * Called during shutdown of siproxd. Gives the plugin the chance
 * to clean up its mess (e.g. dynamic memory allocation, database
 * connections, whatever the plugin messes around with)
 */
int  PLUGIN_END(plugin_def_t *plugin_def){
   INFO("plugin_fix_fbox_anoncall ends here");
   return STS_SUCCESS;
}


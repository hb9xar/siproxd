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

#include <stdlib.h>
#include <string.h>
#include <regex.h>

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
extern struct urlmap_s urlmap[];		/* URL mapping table     */

/* plugin configuration storage */
static struct plugin_config {
   stringa_t trunk_name;
   stringa_t trunk_account;
   stringa_t trunk_numbers_regex;
} plugin_cfg;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
   { "plugin_siptrunk_name",          TYP_STRINGA,&plugin_cfg.trunk_name,	{0, NULL} },
   { "plugin_siptrunk_account",       TYP_STRINGA,&plugin_cfg.trunk_account,	{0, NULL} },
   { "plugin_siptrunk_numbers_regex", TYP_STRINGA,&plugin_cfg.trunk_numbers_regex,	{0, NULL} },
   {0, 0, 0}
};

/* local storage needed for regular expression handling */
static regex_t *re;

/* Prototypes */
static int plugin_siptrunk_init(void);
static int plugin_siptrunk_process(sip_ticket_t *ticket);
static regmatch_t * rmatch (char *buf, regex_t *re);


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

   return plugin_siptrunk_init();
}

/*
 * Processing.
 * 
 */
int  PLUGIN_PROCESS(int stage, sip_ticket_t *ticket){
   /* stage contains the PLUGIN_* value - the stage of SIP processing. */
   return plugin_siptrunk_process(ticket);
}

/*
 * De-Initialization.
 * Called during shutdown of siproxd. Gives the plugin the chance
 * to clean up its mess (e.g. dynamic memory allocation, database
 * connections, whatever the plugin messes around with)
 */
int  PLUGIN_END(plugin_def_t *plugin_def){
   return STS_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*
 * Workload code
 */
static int plugin_siptrunk_init(void) {
   int i;
   int sts, retsts;
   int num_entries;
   char errbuf[256];

   retsts = STS_SUCCESS;

   /* check for equal entries of trunk_name and trunk_account */
   if (plugin_cfg.trunk_name.used != plugin_cfg.trunk_account.used) {
      ERROR("Plugin '%s': number of trunks (%i) and number of "
            "accounts (%i) differ!", name,
            plugin_cfg.trunk_name.used, plugin_cfg.trunk_account.used);
      return STS_FAILURE;
   }

   if (plugin_cfg.trunk_name.used != plugin_cfg.trunk_numbers_regex.used) {
      ERROR("Plugin '%s': number of trunks (%i) and number of "
            "number blocks (%i) differ!", name,
            plugin_cfg.trunk_name.used, plugin_cfg.trunk_numbers_regex.used);
      return STS_FAILURE;
   }

   /* allocate space for regexes and compile them */
   num_entries = plugin_cfg.trunk_numbers_regex.used;
   re = malloc(num_entries*sizeof(re[0]));
   for (i=0; i < num_entries; i++) {
      sts = regcomp (&re[i], plugin_cfg.trunk_numbers_regex.string[i],
                     REG_ICASE|REG_EXTENDED);
      if (sts != 0) {
         regerror(sts, &re[i], errbuf, sizeof(errbuf));
         ERROR("Regular expression [%s] failed to compile: %s", 
               plugin_cfg.trunk_numbers_regex.string[i], errbuf);
         retsts = STS_FAILURE;
      }
   }
   DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: %i regular expressions compiled", i);
   return retsts;
}

static int plugin_siptrunk_process(sip_ticket_t *ticket) {
   int sts=STS_SUCCESS;
   int i, j;
   osip_uri_t *req_url = NULL;
   osip_uri_t *to_url = NULL;
   osip_uri_t *url = NULL;

   /* plugin loaded and not configured, return with success */
   if (plugin_cfg.trunk_numbers_regex.used==0) return STS_SUCCESS;

   if (ticket->direction == DIRTYP_UNKNOWN) {
      sip_find_direction(ticket, NULL);
   }

   DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: type=%i", ticket->direction);
   DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: next hop was %s:%i",
          utils_inet_ntoa(ticket->next_hop.sin_addr),
          ticket->next_hop.sin_port);

   /* SIP request? && direction undetermined? */
   if ((ticket->direction == DIRTYP_UNKNOWN) 
        && MSG_IS_REQUEST(ticket->sipmsg)) {
      DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: processing REQ w/ DIRTYP_UNKNOWN");

      /* get REQ URI & To URI from headers */
      req_url=osip_message_get_uri(ticket->sipmsg);
      if (req_url && req_url->username) {
         DEBUGC(DBCLASS_BABBLE, "Request URI: [%s]", req_url->username);
      }

      /* check To: URI */
      to_url=ticket->sipmsg->to->url;
      if (to_url && to_url->username) {
         DEBUGC(DBCLASS_BABBLE, "To: header: [%s]", to_url->username);
      }

      /* Loop through config array */
      for (i = 0; i < plugin_cfg.trunk_numbers_regex.used; i++) {
         regmatch_t *pmatch_uri = NULL;
         regmatch_t *pmatch_to  = NULL;

         /* check SIP URI */
         if (req_url && req_url->username) {
            pmatch_uri = rmatch(req_url->username, &re[i]);
         }

         /* check To: URI */
         if (to_url && to_url->username) {
            pmatch_to = rmatch(to_url->username, &re[i]);
         }

         if ((pmatch_uri == NULL) && (pmatch_to == NULL)) continue;

         /* have a match */
         DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: matched trunk on rule %i [%s]",
                i, plugin_cfg.trunk_numbers_regex.string[i] );
         DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: Trunk [%s], Account [%s]",
                plugin_cfg.trunk_name.string[i], 
                plugin_cfg.trunk_account.string[i]);


         /* prepare URL structure for compare) */
         osip_uri_init(&url);
         sts = osip_uri_parse(url, plugin_cfg.trunk_account.string[i]);
         if (sts != 0) {
            WARN("parsing plugin_siptrunk_account [%s] failed.", 
                 plugin_cfg.trunk_account.string[i]);
            continue;
         }

         /* search for an Account entry in registration DB */
         for (j=0; j<URLMAP_SIZE; j++){
            if (urlmap[j].active == 0) continue;

            if (compare_url(url, urlmap[j].reg_url) == STS_SUCCESS) {
               DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: found registered client, idx=%i",j);

               /* set ticket->direction == REQTYP_INCOMING */
               ticket->direction = REQTYP_INCOMING;

               /* set next jop host & port */
               sts = get_ip_by_host(osip_uri_get_host(urlmap[j].true_url), 
                                    &ticket->next_hop.sin_addr);
               if (sts == STS_FAILURE) {
                  DEBUGC(DBCLASS_PROXY, "plugin_siptrunk: cannot resolve URI [%s]",
                         osip_uri_get_host(urlmap[j].true_url));
                  return STS_FAILURE;
               }

               ticket->next_hop.sin_port=SIP_PORT;
               if (osip_uri_get_port(urlmap[j].true_url)) {
                  ticket->next_hop.sin_port=atoi(osip_uri_get_port(urlmap[j].true_url));
                  if (ticket->next_hop.sin_port == 0) {
                     ticket->next_hop.sin_port=SIP_PORT;
                  }
               }

               break;
            }
         
         }
         if (url) {osip_uri_free(url);}


         /* only do first match, then break */
         break;
      } /* end for i */


      if (i >= plugin_cfg.trunk_numbers_regex.used) {
         DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: no match");
      }

      DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: next hop is now %s:%i",
             utils_inet_ntoa(ticket->next_hop.sin_addr),
             ticket->next_hop.sin_port);
 
   } else {
      DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: not processing SIP message");
   }
   DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: exit");
   return STS_SUCCESS;
}

/*
 * This regex replacement code has been proudly borrowed from
 * http://www.daniweb.com/software-development/c/code/216955#
 *
 * buf: input string + output result
 * rp: replacement string, will be destroyed during processing!
 * size: size of buf and rp
 * re: regex to process
 *
 * rmatch() performs the initial regexec match, and if a match is found
 * it returns a pointer to the regmatch array which contains the result
 * of the match.
 *
 * This eliminates the need to copy the 'rp' string before knowing
 * if a match is actually there.
 */
#define NMATCHES 10
static regmatch_t * rmatch (char *buf, regex_t *re) {
   static regmatch_t pm[NMATCHES]; /* regoff_t is int so size is int */

   /* perform the match */
   if (regexec (re, buf, NMATCHES, pm, 0)) {
      return NULL;
   }
   return &pm[0];
}

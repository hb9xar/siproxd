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
static regmatch_t * rmatch (char *buf, int size, regex_t *re);
//static int rreplace (char *buf, int size, regex_t *re, regmatch_t pmatch[], char *rp);


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
   osip_uri_t *req_url;
   osip_uri_t *to_url;
   osip_uri_t *url;
//   char *req_url_string=NULL;
//   char *to_url_string=NULL;

   #define WORKSPACE_SIZE 128
//   static char in[WORKSPACE_SIZE+1], rp[WORKSPACE_SIZE+1];

   /* plugin loaded and not configured, return with success */
   if (plugin_cfg.trunk_numbers_regex.used==0) return STS_SUCCESS;


   DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: type=%i", ticket->direction);
   DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: next hop was %s:%i",
          utils_inet_ntoa(ticket->next_hop.sin_addr),
          ticket->next_hop.sin_port);

   /* SIP request? && direction undetermined? */
   if (MSG_IS_REQUEST(ticket->sipmsg)) {
//   if ((ticket->direction == DIRTYP_UNKNOWN) 
//        && MSG_IS_REQUEST(ticket->sipmsg)) {
      DEBUGC(DBCLASS_PLUGIN, "plugin_siptrunk: processing REQ w/ DIRTYP_UNKNOWN");


      /* Loop through config array */
      for (i = 0; i < plugin_cfg.trunk_numbers_regex.used; i++) {
         regmatch_t *pmatch_uri = NULL;
         regmatch_t *pmatch_to  = NULL;

         /* check SIP URI */
         req_url=osip_message_get_uri(ticket->sipmsg);
         if (req_url && req_url->username) {
            DEBUGC(DBCLASS_BABBLE, "Request URI: [%s]", req_url->username);
            pmatch_uri = rmatch(req_url->username, WORKSPACE_SIZE, &re[i]);
         }

         /* check To: URI */
         to_url=osip_to_get_url(ticket->sipmsg);
         if (to_url && to_url->username) {
            DEBUGC(DBCLASS_BABBLE, "To: header: [%s]", to_url->username);
            pmatch_uri = rmatch(to_url->username, WORKSPACE_SIZE, &re[i]);
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
         osip_uri_parse(url, plugin_cfg.trunk_account.string[i]);

         /* search for an Account entry in registration DB */
         for (j=0; j<URLMAP_SIZE; j++){
            if (urlmap[j].active == 0) continue;

            if (compare_url(url, urlmap[j].reg_url) == STS_SUCCESS) {
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
         osip_uri_free(url);


         /* only do first match, then break */
         break;
      } /* end for */

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
 * Afterwards rreplace() is to be called, providing this regmatch array.
 *
 * This eliminates the need to copy the 'rp' string before knowing
 * if a match is actually there.
 */
#define NMATCHES 10
static regmatch_t * rmatch (char *buf, int size, regex_t *re) {
   static regmatch_t pm[NMATCHES]; /* regoff_t is int so size is int */

   /* perform the match */
   if (regexec (re, buf, NMATCHES, pm, 0)) {
      return NULL;
   }
   return &pm[0];
}

#if 0
static int rreplace (char *buf, int size, regex_t *re, regmatch_t pmatch[], char *rp) {
   char *pos;
   int sub, so, n;

   /* match(es) found: */
   for (pos = rp; *pos; pos++) {
      /* back references \1 ... \9: expand them in 'rp' */
      if (*pos == '\\' && *(pos + 1) > '0' && *(pos + 1) <= '9') {
         so = pmatch[*(pos + 1) - 48].rm_so;	/* pmatch[1..9] */
         n = pmatch[*(pos + 1) - 48].rm_eo - so;
         if (so < 0 || strlen (rp) + n - 1 > size) return STS_FAILURE;
         memmove (pos + n, pos + 2, strlen (pos) - 1);
         memmove (pos, buf + so, n);
         pos = pos + n - 2;
      }
   }

   sub = pmatch[1].rm_so; /* no repeated replace when sub >= 0 */
   /* and replace rp in the input buffer */
   for (pos = buf; !regexec (re, pos, 1, pmatch, 0); ) {
      n = pmatch[0].rm_eo - pmatch[0].rm_so;
      pos += pmatch[0].rm_so;
      if (strlen (buf) - n + strlen (rp) > size) {
         return STS_FAILURE;
      }
      memmove (pos + strlen (rp), pos + n, strlen (pos) - n + 1);
      memmove (pos, rp, strlen (rp));
      pos += strlen (rp);
      if (sub >= 0) break;
   }
   return STS_SUCCESS;
}
#endif

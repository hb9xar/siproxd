/*
    Copyright (C) 2002-2011  Thomas Ries <tries@gmx.net>

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

/*
 * This plugin adds a regular expression rewrite support
 * for SIP targets.
 */


/* must be defined before including <plugin.h> */
#define PLUGIN_NAME	plugin_regex_body

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "plugins.h"
#include "redirect_cache.h"
#include "log.h"

/* Plug-in identification */
static char name[]="plugin_regex_body";
static char desc[]="Use regular expressions to rewrite SIP message bodies";

/* global configuration storage - required for config file location */
extern struct siproxd_config configuration;

/* constants */
#define REDIRECTED_TAG "redirected"
#define REDIRECTED_VAL "regex"

/* plugin configuration storage */
static struct plugin_config {
   stringa_t regex_body_desc;
   stringa_t regex_body_pattern;
   stringa_t regex_body_replace;
} plugin_cfg;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
   { "plugin_regex_body_desc",     TYP_STRINGA,&plugin_cfg.regex_body_desc,	{0, NULL} },
   { "plugin_regex_body_pattern",  TYP_STRINGA,&plugin_cfg.regex_body_pattern,	{0, NULL} },
   { "plugin_regex_body_replace",  TYP_STRINGA,&plugin_cfg.regex_body_replace,	{0, NULL} },
   {0, 0, 0}
};

/* local storage needed for regular expression handling */
static regex_t *re;
/* Redirect Cache: Queue Head is static */
static redirected_cache_element_t redirected_cache;


/* local prototypes */
static int plugin_regex_body_init(void);
static int plugin_regex_body_process(sip_ticket_t *ticket);
static int plugin_regex_body_redirect(sip_ticket_t *ticket);
static regmatch_t * rmatch (char *buf, int size, regex_t *re);
static int rreplace (char *buf, int size, regex_t *re, regmatch_t pmatch[], char *rp);


/* 
 * Plugin API functions code
 */
/* Initialization */
int  PLUGIN_INIT(plugin_def_t *plugin_def) {
   plugin_def->api_version=SIPROXD_API_VERSION;
   plugin_def->name=name;
   plugin_def->desc=desc;
   plugin_def->exe_mask=PLUGIN_DETERMINE_TARGET;

   /* read the config file */
   if (read_config(configuration.configfile,
                   configuration.config_search,
                   plugin_cfg_opts, name) == STS_FAILURE) {
      ERROR("Plugin '%s': could not load config file", name);
      return STS_FAILURE;
   }
   
   return plugin_regex_body_init();
}

/* Processing */
int  PLUGIN_PROCESS(int stage, sip_ticket_t *ticket){
   int sts;
   sts=plugin_regex_body_process(ticket);
   return sts;
}

/* De-Initialization */
int  PLUGIN_END(plugin_def_t *plugin_def){
   int i;
   int num_entries;

   /* free space for regexes */
   num_entries = plugin_cfg.regex_body_pattern.used;
   for (i=0; i < num_entries; i++) {
      regfree(&re[i]);
   }
   free(re);
   return STS_SUCCESS;
}


/*
 * Workload code
 */
static int plugin_regex_body_init(void) {
   int i;
   int sts, retsts;
   int num_entries;
   char errbuf[256];

   retsts = STS_SUCCESS;

   /* check for equal entries of patterns and replacements */
   if (plugin_cfg.regex_body_pattern.used != plugin_cfg.regex_body_replace.used) {
      ERROR("Plugin '%s': number of search patterns (%i) and number of "
            "replacement patterns (%i) differ!", name,
            plugin_cfg.regex_body_pattern.used, plugin_cfg.regex_body_replace.used);
      return STS_FAILURE;
   }

   if (plugin_cfg.regex_body_pattern.used != plugin_cfg.regex_body_desc.used) {
      ERROR("Plugin '%s': number of search patterns (%i) and number of "
            "descriptions (%i) differ!", name,
            plugin_cfg.regex_body_pattern.used, plugin_cfg.regex_body_desc.used);
      return STS_FAILURE;
   }

   /* allocate space for regexes and compile them */
   num_entries = plugin_cfg.regex_body_pattern.used;
   re = malloc(num_entries*sizeof(re[0]));
   for (i=0; i < num_entries; i++) {
      sts = regcomp (&re[i], plugin_cfg.regex_body_pattern.string[i],
                     REG_ICASE|REG_EXTENDED);
      if (sts != 0) {
         regerror(sts, &re[i], errbuf, sizeof(errbuf));
         ERROR("Regular expression [%s] failed to compile: %s", 
               plugin_cfg.regex_body_pattern.string[i], errbuf);
         retsts = STS_FAILURE;
      }
   }
   
   return retsts;
}
/* returns STS_SIP_SENT if processing is to be terminated,
 * otherwise STS_SUCCESS (go on with processing) */
/* code (entry point) */
static int plugin_regex_body_process(sip_ticket_t *ticket) {
   int sts=STS_SUCCESS;
   osip_uri_t *req_url;
   osip_uri_t *to_url;
   osip_generic_param_t *r=NULL;

   /* plugin loaded and not configured, return with success */
   if (plugin_cfg.regex_body_pattern.used==0) return STS_SUCCESS;
   if (plugin_cfg.regex_body_replace.used==0) return STS_SUCCESS;

   DEBUGC(DBCLASS_PLUGIN,"plugin entered");

   sts=plugin_regex_body_redirect(ticket);

   return sts;
}


/* private plugin code */
static int plugin_regex_body_redirect(sip_ticket_t *ticket) {
   int sts;
   osip_message_t *mymsg=ticket->sipmsg;
   osip_body_t *body;
   char* body_string;
   size_t body_length;
   char clen[8];

   #define WORKSPACE_SIZE 1024
   static char in[WORKSPACE_SIZE+1], rp[WORKSPACE_SIZE+1];

   sts = osip_message_get_body(mymsg, 0, &body);
   if (sts != 0) {
      DEBUGC(DBCLASS_PROXY, "rewrite_invitation_body: "
                            "no body found in message");
      return STS_SUCCESS;
   }
   sts = sip_body_to_str(body, &body_string, &body_length);

   /* perform search and replace of the regexes, first match hits */
   for (int i = 0; i < plugin_cfg.regex_body_pattern.used; i++) {
      regmatch_t *pmatch = NULL;
      pmatch = rmatch(body_string, WORKSPACE_SIZE, &re[i]);
      if (pmatch == NULL) continue; /* no match, next */

      /* have a match, do the replacement */
      INFO("Matched rexec rule: %s",plugin_cfg.regex_body_desc.string[i] );
      strncpy (in, body_string, WORKSPACE_SIZE);
      in[WORKSPACE_SIZE]='\0';
      strncpy (rp, plugin_cfg.regex_body_replace.string[i], WORKSPACE_SIZE);
      rp[WORKSPACE_SIZE]='\0';

      for (int match_num = 0; match_num < sizeof(pmatch); match_num++) {
         sts = rreplace(in, WORKSPACE_SIZE, &re[i], pmatch, rp);
         if (sts != STS_SUCCESS) {
            ERROR("regex replace failed: pattern:[%s] replace:[%s]",
                  plugin_cfg.regex_body_pattern.string[i],
                  plugin_cfg.regex_body_replace.string[i]);
            return STS_FAILURE;
         }
      }
      body_string = in;
   }

   sts = osip_list_remove(&(mymsg->bodies), 0);
   osip_free(body);
   body_length=strlen(body_string);
   sip_message_set_body(mymsg, body_string, body_length);
   osip_content_length_free(mymsg->content_length);
   mymsg->content_length=NULL;
   sprintf(clen,"%ld", (long) body_length);
   sts = osip_message_set_content_length(mymsg, clen);

   return sts;
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

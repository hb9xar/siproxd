/*
    Copyright (C) 2008  Thomas Ries <tries@gmx.net>

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

#include "config.h"

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



/* 
 * Initialization.
 * Called once suring siproxd startup.
 */
int  plugin_init(plugin_def_t *plugin_def) {
   /* API version number of siproxd that this plugin is built against.
    * This constant will change whenever changes to the API are made
    * that require adaptions in the plugin. */
   plugin_def->api_version=SIPROXD_API_VERSION;

   /* Name and descriptive text of the plugin */
   plugin_def->name=strdup("plugin_demo");
   plugin_def->desc=strdup("This is just a demo plugin without any purpose");

   /* Execution mask - during what stages of SIP processing shall
    * the plugin be called. */
   plugin_def->exe_mask=PLUGIN_DETERMINE_TARGET|PLUGIN_PRE_PROXY;

   INFO("plugin_demo is initialized");
   return STS_SUCCESS;
}

/*
 * Processing.
 * 
 */
int  plugin_process(int stage, sip_ticket_t *ticket){
   /* stage contains the PLUGIN_* value - the stage of SIP processing. */
   INFO("plugin_demo: processing - stage %i",stage);
   return STS_SUCCESS;
}

/*
 * De-Initialization.
 * Called during shutdown of siproxd. Gives the plugin the chance
 * to clean up its mess (e.g. dynamic memory allocation, database
 * connections, whatever the plugin messes around with)
 */
int  plugin_end(plugin_def_t *plugin_def){
   /* free my allocated rescources */
   if (plugin_def->name) {free(plugin_def->name); plugin_def->name=NULL;}
   if (plugin_def->desc) {free(plugin_def->desc); plugin_def->desc=NULL;}

   INFO("plugin_demo ends here");
   return STS_SUCCESS;
}


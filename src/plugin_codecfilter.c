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
#define PLUGIN_NAME	plugin_codecfilter

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
static char name[]="plugin_codecfilter";
static char desc[]="Allows filtering the codec list in SDP";

/* global configuration storage - required for config file location */
extern struct siproxd_config configuration;

/* plugin configuration storage */
static struct plugin_config {
   char *codec;
   stringa_t codec_whitelist;
   stringa_t codec_blacklist;
} plugin_cfg;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
   { "plugin_codecfilter_whitelist",      TYP_STRINGA, &plugin_cfg.codec_whitelist,	{0, NULL} },
   { "plugin_codecfilter_blacklist",      TYP_STRINGA, &plugin_cfg.codec_blacklist,	{0, NULL} },
   {0, 0, 0}
};

/* Prototypes */
static int sdp_filter_codec(sdp_message_t *sdp);

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
   int sts;
   char *buff;
   size_t buflen;
   char clen[8]; /* content length: probably never more than 7 digits !*/
   osip_body_t *body;
   sdp_message_t  *sdp;

DEBUGC(DBCLASS_PLUGIN, "%s: entered", name);

   sts = osip_message_get_body(ticket->sipmsg, 0, &body);
   if (sts != 0) {
      DEBUGC(DBCLASS_PLUGIN, "%s: rewrite_invitation_body: "
                            "no body found in message", name);
      return STS_SUCCESS;
   }

   sts = sip_body_to_str(body, &buff, &buflen);
   if (sts != 0) {
      ERROR("%s: unable to sip_body_to_str", name);
      return STS_FAILURE;
   }

   sts = sdp_message_init(&sdp);
   sts = sdp_message_parse (sdp, buff);
   if (sts != 0) {
      ERROR("%s: unable to sdp_message_parse body", name);
      DUMP_BUFFER(-1, buff, buflen);
      osip_free(buff);
      sdp_message_free(sdp);
      return STS_SUCCESS;
   }
   osip_free(buff);
   buff=NULL;


   // do the magic...
   sdp_filter_codec(sdp);


   /* remove old body */
   sts = osip_list_remove(&(ticket->sipmsg->bodies), 0);
   osip_body_free(body);
   body=NULL;

   /* dump new body */
   sdp_message_to_str(sdp, &buff);
   buflen=strlen(buff);

   /* free sdp structure */
   sdp_message_free(sdp);

   /* include new body */
   sip_message_set_body(ticket->sipmsg, buff, buflen);
   if (sts != 0) {
      ERROR("%s: unable to sip_message_set_body body", name);
   }

   /* free content length resource and include new one*/
   osip_content_length_free(ticket->sipmsg->content_length);
   ticket->sipmsg->content_length=NULL;
   sprintf(clen,"%ld",(long)buflen);
   sts = osip_message_set_content_length(ticket->sipmsg, clen);

   /* free new body string*/
   osip_free(buff);


DEBUGC(DBCLASS_PLUGIN, "%s: exit", name);
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

/*--------------------------------------------------------------------*/
static int sdp_filter_codec(sdp_message_t *sdp) {
   int sts;
   int i;
   char *sdp_media;
   int media_stream_no;

   char *payload;
   int payload_mediatype;
   int payload_no;

   sdp_attribute_t *sdp_attr;
   int attr_mediatype;
   int media_attr_no;
   int skip_media_attr_inc;

   media_stream_no=0;
   while ((sdp_media=sdp_message_m_media_get(sdp, media_stream_no))) {
      DEBUGC(DBCLASS_PLUGIN, "%s: m:%i", name, media_stream_no);

      payload_no=0;
      while ((payload=sdp_message_m_payload_get(sdp, media_stream_no, payload_no))) {
         DEBUGC(DBCLASS_PLUGIN, " +-- p:%s", payload);
         payload_no++;
      }

      media_attr_no=0;
      while ((sdp_attr=sdp_message_attribute_get(sdp, media_stream_no, media_attr_no))) {
         DEBUGC(DBCLASS_PLUGIN, "     Attr m:%i, a=%i", media_stream_no, media_attr_no);
         if (sdp_attr->a_att_field && sdp_attr->a_att_value) {
            attr_mediatype=0;
            sts=sscanf(sdp_attr->a_att_value, "%i", &attr_mediatype);

            DEBUGC(DBCLASS_PLUGIN, "     Attr field=%s, val=%s [MT=%i]", 
                   sdp_attr->a_att_field, sdp_attr->a_att_value, attr_mediatype);


            /* search for match */
            for (i=0; i<plugin_cfg.codec_blacklist.used; i++) {
               if (strcasestr(sdp_attr->a_att_value, plugin_cfg.codec_blacklist.string[i])) {
                  /* match, need to remove this codec */
                  DEBUGC(DBCLASS_PLUGIN, "%s: *** REMOVE media attr [%s] at attrpos=%i", name, 
                         sdp_attr->a_att_value, media_attr_no);

                  // remove media attribute (a)
                  // libosip bug?? -> loops Do it manually then...
                  //if (sdp_message_a_attribute_del_at_index(sdp, media_stream_no, sdp_attr->a_att_field, media_attr_no) != OSIP_SUCCESS) {
                  //   ERROR("%s: sdp_message_a_attribute_del() failed", name);
                  //}
                  {
                  sdp_media_t *med;
                  sdp_attribute_t *attr;
                  med = (sdp_media_t *) osip_list_get(&sdp->m_medias, media_stream_no);

                  if ((attr = osip_list_get(&med->a_attributes, media_attr_no)) != NULL) {
                     osip_list_remove(&med->a_attributes, media_attr_no);
                     sdp_attribute_free(attr);
                     attr=NULL;
                     skip_media_attr_inc=1;
                  }
                  }

                  // find corresponding (m) payload
                  payload_no=0;
                  while ((payload=sdp_message_m_payload_get(sdp, media_stream_no, payload_no))) {
                     payload_mediatype=0;
                     sts=sscanf(payload, "%i", &payload_mediatype);
                     DEBUGC(DBCLASS_PLUGIN, " +-- p:%s [%i]", payload, payload_mediatype);
                     if (payload_mediatype == attr_mediatype) {
                        DEBUGC(DBCLASS_PLUGIN, "%s: *** REMOVE media format %i at stream=%i, pos=%i", name, 
                               payload_mediatype, media_stream_no, payload_no);

                        // remove (m) playload in media description
                        if (sdp_message_m_payload_del(sdp, media_stream_no, payload_no) != OSIP_SUCCESS) {
                           ERROR("%s: sdp_message_a_attribute_del() failed", name);
                        }
                     } else {
                        payload_no++;
                     }
                  } /* while playload */
               } /* if match with config blacklist */
            } /* for codec_blacklist */

         }
         if (skip_media_attr_inc == 0) {media_attr_no++;}
         skip_media_attr_inc=0;
      } /* while sdp_message_attribute_get */

      media_stream_no++;
   } /* while sdp_message_m_media_get */



   return STS_SUCCESS;
}

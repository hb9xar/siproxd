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

#include <stdlib.h>
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
   stringa_t codec_blacklist;
} plugin_cfg;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
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
   osip_body_t *body;
   sdp_message_t  *sdp;
   int content_length;
   osip_content_type_t *content_type;
   char clen[8]; /* content length: probably never more than 7 digits !*/

   //
   // check that we have the expected payload "application/sdp"
   //

   // get content length
   content_length=0;
   if (ticket->sipmsg && ticket->sipmsg->content_length 
       && ticket->sipmsg->content_length->value) {
      sts=sscanf(ticket->sipmsg->content_length->value, "%i", &content_length);
   }

   // check if we have a content type defined and that payload length >0
   content_type=osip_message_get_content_type(ticket->sipmsg);
   if ((content_length == 0) || (content_type == NULL) 
       || (content_type->type == NULL) || (content_type->subtype == NULL)) {
      DEBUGC(DBCLASS_PLUGIN, "%s: no content", name);
      return STS_SUCCESS;
   }

   // check content type: must be "application/sdp"
   if ((strncmp(content_type->type, "application", sizeof("application")) != 0)
       || (strncmp(content_type->subtype, "sdp", sizeof("sdp")) != 0)) {
      DEBUGC(DBCLASS_PLUGIN, "%s: unsupported content-type %s/%s", name,
             content_type->type, content_type->subtype);
      return STS_SUCCESS;
   }

   DEBUGC(DBCLASS_PLUGIN, "%s: content-type %s/%s, size=%i", name, 
          content_type->type, content_type->subtype, content_length);

   //
   // parse the payload
   //

   // get a pointer to the payload of the SIP packet
   sts = osip_message_get_body(ticket->sipmsg, 0, &body);
   if (sts != 0) {
      DEBUGC(DBCLASS_PLUGIN, "%s: no body found in message", name);
      return STS_SUCCESS;
   }
   // dump it into a buffer
   sts = sip_body_to_str(body, &buff, &buflen);
   if (sts != 0) {
      WARN("%s: unable to sip_body_to_str", name);
      return STS_SUCCESS;
   }
   // and parse it into an SDP structure
   sts = sdp_message_init(&sdp);
   sts = sdp_message_parse (sdp, buff);
   if (sts != 0) {
      WARN("%s: unable to sdp_message_parse() body", name);
      DUMP_BUFFER(-1, buff, buflen);
      osip_free(buff);
      buff=NULL;
      sdp_message_free(sdp);
      return STS_SUCCESS;
   }
   osip_free(buff);
   buff=NULL;

   //
   // now do the codec filtering magic...
   sdp_filter_codec(sdp);

   //
   // replace the original payload with the new modified payload
   //
   
   // remove old body from SIP packet
   sts = osip_list_remove(&(ticket->sipmsg->bodies), 0);
   osip_body_free(body);
   body=NULL;

   // dump new body to buffer
   sdp_message_to_str(sdp, &buff);
   buflen=strlen(buff);

   // free sdp structure (no longer needed)
   sdp_message_free(sdp);
   sdp=NULL;

   // put new body into SIP message
   sts=sip_message_set_body(ticket->sipmsg, buff, buflen);
   if (sts != 0) {
      ERROR("%s: unable to sip_message_set_body body", name);
      DUMP_BUFFER(-1, buff, buflen);
      buflen=0;
   }
   // free buffer
   osip_free(buff);
   buff=NULL;

   //
   // set new content length
   //

   // remove old content leght field
   osip_content_length_free(ticket->sipmsg->content_length);
   ticket->sipmsg->content_length=NULL;

   // set new content length
   sprintf(clen,"%ld",(long)buflen);
   sts = osip_message_set_content_length(ticket->sipmsg, clen);

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
   // SDP payload list processing
   char *payload;
   int payload_mediatype;
   int payload_no;
   // SDP attribute list processing
   sdp_attribute_t *sdp_attr;
   int attr_mediatype;
   int media_attr_no;
   int skip_media_attr_inc=0;

   //
   // loop through all media descriptions (normal phone call has 1 stream, a video call
   // may have multiple streams)
   //
   media_stream_no=0;
   while ((sdp_media=sdp_message_m_media_get(sdp, media_stream_no))) {

      //
      // loop through all media attributes of this media stream
      //
      media_attr_no=0;
      while ((sdp_attr=sdp_message_attribute_get(sdp, media_stream_no, media_attr_no))) {
         DEBUGC(DBCLASS_PLUGIN, "  +--Attr m:%i, a=%i", media_stream_no, media_attr_no);
         // check if attribute field and value exist
         if (sdp_attr->a_att_field && sdp_attr->a_att_value) {
            // fetch the media type value (first number field in value)
            attr_mediatype=0;
            sts=sscanf(sdp_attr->a_att_value, "%i", &attr_mediatype);
            DEBUGC(DBCLASS_PLUGIN, "     +--Attr field=%s, val=%s [MT=%i]", 
                   sdp_attr->a_att_field, sdp_attr->a_att_value, attr_mediatype);

            //
            // loop through all configured "blacklisted" media strings
            // and look for a match
            //
            for (i=0; i<plugin_cfg.codec_blacklist.used; i++) {
               // do an *case-insensitive* *substring* match
               if (strcasestr(sdp_attr->a_att_value, plugin_cfg.codec_blacklist.string[i])) {
                  // match, need to remove this codec
                  DEBUGC(DBCLASS_PLUGIN, "%s: blacklisted - removing media attr [%s] at attrpos=%i", name, 
                         sdp_attr->a_att_value, media_attr_no);

                  //
                  // remove media attribute (a)
                  //
                  
                  // libosip bug?? -> the following coda causes an infinite loop inside libosip2.
                  //if (sdp_message_a_attribute_del_at_index(sdp, media_stream_no, sdp_attr->a_att_field, media_attr_no) != OSIP_SUCCESS) {
                  //   ERROR("%s: sdp_message_a_attribute_del() failed", name);
                  //}

                  // #&%+!@ -> So it manually...
                  {
                     sdp_media_t *med;
                     sdp_attribute_t *attr;
                     med = (sdp_media_t *) osip_list_get(&sdp->m_medias, media_stream_no);

                     if ((attr = osip_list_get(&med->a_attributes, media_attr_no)) != NULL) {
                        osip_list_remove(&med->a_attributes, media_attr_no);
                        sdp_attribute_free(attr);
                        attr=NULL;
                        // as I have removed the current attribute, all other
                        // attributes are shifted one down, so for the next iteration
                        // I must not increment the index or I will skip one attribute
                        skip_media_attr_inc=1;
                     }
                  }

                  //
                  // find corresponding (m) payload and remove it as well$
                  //
                  
                  // loop through all payloads of the current media description
                  payload_no=0;
                  while ((payload=sdp_message_m_payload_get(sdp, media_stream_no, payload_no))) {
                     // extract the media type from the payload
                     payload_mediatype=0;
                     sts=sscanf(payload, "%i", &payload_mediatype);
                     DEBUGC(DBCLASS_PLUGIN, "     +-- payload:%s MT=%i", payload, payload_mediatype);
                     // medfia type matches?
                     if (payload_mediatype == attr_mediatype) {
                        DEBUGC(DBCLASS_PLUGIN, "%s: blacklisted - removing media format %i at stream=%i, pos=%i", name, 
                               payload_mediatype, media_stream_no, payload_no);
                        // remove (m) playload in media description
                        if (sdp_message_m_payload_del(sdp, media_stream_no, payload_no) != OSIP_SUCCESS) {
                           ERROR("%s: sdp_message_a_attribute_del() failed", name);
                        }
                     } else {
                        // increment index only if the current payload has not been removed
                        // as all other medias would have shifted down.
                        payload_no++;
                     }
                  } /* while playload */
               } /* if match with config blacklist */
            } /* for codec_blacklist */
         } /* if attribute field and value exist */

         // increment index only of the current media attribute has not been deleted
         if (skip_media_attr_inc == 0) {
            media_attr_no++;
         } else {
            skip_media_attr_inc=0;
         }

      } /* while sdp_message_attribute_get */
      media_stream_no++;
   } /* while sdp_message_m_media_get */

   return STS_SUCCESS;
}

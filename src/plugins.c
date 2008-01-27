/*
    Copyright (C) 2003-2008  Thomas Ries <tries@gmx.net>

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

#include <netinet/in.h>
#include <arpa/inet.h>

#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "log.h"
#include "plugins.h"

static char const ident[]="$Id$";

/* configuration storage */
extern struct siproxd_config configuration;

/* Plugin "database" - queue header */
plugin_def_t *siproxd_plugins=NULL;

/* code */
typedef int (*func_plugin_init_t)(plugin_def_t *plugin_def);
typedef int (*func_plugin_process_t)(int stage, sip_ticket_t *ticket);
typedef int (*func_plugin_end_t)(void);


/* 
 * Load the plugins in the order as specified in the config file.
 * This is done once, starts with empty plugin list
 */
int load_plugins (void) {
   int sts;
   int i;
   char path[PATH_STRING_SIZE];

   lt_dlhandle handle=NULL;
   plugin_def_t *cur=NULL;
   plugin_def_t *last=siproxd_plugins;

   func_plugin_init_t plugin_init       = NULL;
   func_plugin_process_t plugin_process = NULL;
   func_plugin_end_t plugin_end         = NULL;

   /* initialize the libtool dynamic loader */
   sts = lt_dlinit();
   if (sts != 0) {
      ERROR("ltdl (libtool dynamic loader) initialization failed.");
      return STS_FAILURE;
   }

   /* find plugins to load from config file */
   for (i=0; i<configuration.load_plugin.used; i++) {
      /* construct the path where the plugin is */
      if (configuration.plugin_dir) {
         strcpy(path, configuration.plugin_dir);
         strcat(path, configuration.load_plugin.string[i]);
      } else {
         strcpy(path, configuration.load_plugin.string[i]);
      }

      /* dlopen() the plugin */
      DEBUGC(DBCLASS_PLUGIN, "load_plugins: opening plugin [%s]", path);
      handle=lt_dlopen(path);

      if (handle == NULL) {
         /* complain and next plugin */
         ERROR("plugin %s not found - skipped", configuration.load_plugin.string[i]);
         continue;
      }

      /* find the plugin_process and plugin_end functions and store them */
      plugin_init    = lt_dlsym (handle, "plugin_init");
      plugin_process = lt_dlsym (handle, "plugin_process");
      plugin_end     = lt_dlsym (handle, "plugin_end");

      DEBUGC(DBCLASS_PLUGIN, "load_plugins: init=%p, process=%p, end=%p",
             plugin_init, plugin_process, plugin_end);

      /* all functions present? */
      if (plugin_init && plugin_process && plugin_end) {
         /* allocate an new item in plugins array */
         cur=malloc(sizeof(plugin_def_t));
         memset(cur,0,sizeof(plugin_def_t));

         /* call the init function */
         sts=(*plugin_init)(cur);

         /* check API version that the plugin was biuilt against */
         if (cur->api_version != SIPROXD_API_VERSION) {
            /* complain and unload the plugin */
            ERROR("Plugin '%s' does not support correct API version. "
                  "Please compile plugin with correct siproxd version.",
                  cur->name);
            sts=(*plugin_end)();
            continue;
         }

         /* store the function pointers */
         cur->plugin_process = plugin_process;
         cur->plugin_end = plugin_end;
         cur->dlhandle = handle;

         /* Tell the user something about the plugin we have just loaded */
         INFO("Plugin '%s' [%s] loaded with %s, exemask=0x%X",
              cur->name, cur->desc, (sts==STS_SUCCESS)?"success":"failure",
              cur->exe_mask);

         /* store forward pointer */
         if (siproxd_plugins == NULL) {
            /* first in chain */
            siproxd_plugins = cur;
            last=cur;
            cur=NULL;
         } else {
            /* not first in chain */
            last->next=(void*)cur;
            last=cur;
            cur=NULL;
         }
      } else {
         /* complain and dlclose the handle...*/
         ERROR("plugin %s does not provide correct API functions - skipped",
               configuration.load_plugin.string[i]);
         lt_dlclose(handle);
      }
   }
   return STS_SUCCESS;
}


/*
 * Called at different stages of SIP processing.
 */
int call_plugins(int stage, sip_ticket_t *ticket) {
   plugin_def_t *cur;
   int sts;
   func_plugin_process_t plugin_process;

   /* sanity check, beware pluigins from crappy stuff */
   if (!ticket || !ticket->sipmsg) return STS_FAILURE;

   /* for each plugin in plugins, do */
   for (cur=siproxd_plugins; cur != NULL; cur = cur->next) {
      /* check stage bitmask, if plugin wants to be called do so */
      if (cur->exe_mask & stage) {
         plugin_process=cur->plugin_process;
         sts=(*plugin_process)(stage, ticket);
         switch (stage) {
            /* PLUGIN_DETERMINE_TARGET can be prematurely ended by plugin - 
               plugin processes and sends the final SIP message itself */
            case (PLUGIN_DETERMINE_TARGET):
               /* return with the plugins status back to the caller */
               if (sts == STS_SIP_SENT) {
                  DEBUGC(DBCLASS_PLUGIN, "call_plugins: prematurely ending "
                         "plugin processing in module %s sts=STS_SIP_SENT",
                         cur->desc);
                  return sts;
               }
               break;
            default:
               break;
         } /* switch*/
      } /* if */
   } /* for */

   return STS_SUCCESS;
}


/*
 * At termination of siproxd "unloads" the plugins.
 * Actually gives the plugins the chance to cleanup whatever they want.
 * The plugins are called in reversed order of loading (last loaded is
 * unloaded first).
 */
int unload_plugins(void) {
   plugin_def_t *cur, *last;
   int sts;
   func_plugin_end_t plugin_end;

   /* for each plugin in plugins do (start at the end of the plugin list) */
   DEBUGC(DBCLASS_PLUGIN, "unloading dynamic plugins");
   
   /* call plugin_end function - the plugin may need to cleanup as well... */
   while (siproxd_plugins) {
      /* search the end */
      last=NULL;
      for (cur=siproxd_plugins; cur->next != NULL; cur = cur->next) {last=cur;}

      plugin_end=cur->plugin_end;
      sts=(*plugin_end)();
      DEBUGC(DBCLASS_PLUGIN, "unload_plugins: '%s' unloaded with %s, ptr=%p",
             cur->name, (sts==STS_SUCCESS)?"success":"failure", cur);

      /* dlclose */
      sts = lt_dlclose(cur->dlhandle);
      if (sts != 0) {
         ERROR("lt_dlclose() failed for plugin %s", cur->name);
      }

      /* deallocate plugins list item */
      if (cur->name) {free(cur->name); cur->name=NULL;}
      if (cur->desc) {free(cur->desc); cur->desc=NULL;}

      if (last) last->next=NULL;
      free(cur);

      /* I don't like this */
      if (cur == siproxd_plugins) siproxd_plugins=NULL;
   }

   /* shutdown ltdl */
   sts = lt_dlexit();
   if (sts != 0) {
      ERROR("lt_dlexit() failed");
   }

   return STS_SUCCESS;
}

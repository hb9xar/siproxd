/*
    Copyright (C) 2002  Thomas Ries <tries@gmx.net>

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


#include "config.h"
#include "log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <syslog.h>


static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";


int log_to_syslog=0;
int debug_pattern=0;


void log_set_pattern(int pattern) {
   debug_pattern=pattern;
}

int  log_get_pattern(void) {
   return debug_pattern;
}

void log_set_tosyslog(int tosyslog) {
   log_to_syslog=tosyslog;
}

/* for all the LOGGING routines:
   They should figure out if we are running as a daemon, then write
   their stuff to syslog or something like that
*/


void log_debug(int class, char *file, int line, const char *format, ...) {
   va_list ap;
   time_t t;
   struct tm *tim;
   char string[128];


   if ((debug_pattern & class) == 0) return;

   va_start(ap, format);

   if (! log_to_syslog) {
      /* not running as daemon - log to STDERR */
      time(&t);
      tim=localtime(&t);
      fprintf(stderr,"%2.2i:%2.2i:%2.2i %s:%i ", tim->tm_hour,
                      tim->tm_min, tim->tm_sec, file, line);
      vfprintf(stderr, format, ap);
      fprintf(stderr,"\n");
   } else {
      /* running as daemon - log via SYSLOG facility */
      vsnprintf(string, sizeof(string), format, ap);
      syslog(LOG_USER|LOG_DEBUG, "%s:%i %s", file, line, string);
   }

   va_end(ap);
   fflush(stderr);
   return;

}


void log_error(char *file, int line, const char *format, ...) {
   va_list ap;
   time_t t;
   struct tm *tim;
   char string[128];

   va_start(ap, format);

   if (! log_to_syslog) {
      /* not running as daemon - log to STDERR */
      time(&t);
      tim=localtime(&t);
      fprintf(stderr,"%2.2i:%2.2i:%2.2i ERROR:%s:%i ",tim->tm_hour,
                      tim->tm_min, tim->tm_sec, file, line);
      vfprintf(stderr, format, ap);
      fprintf(stderr,"\n");
   } else {
      /* running as daemon - log via SYSLOG facility */
      vsnprintf(string, sizeof(string), format, ap);
      syslog(LOG_USER|LOG_WARNING, "%s:%i ERROR:%s", file, line, string);
   }

   va_end(ap);
   fflush(stderr);
   return;

}


void log_warn(char *file, int line, const char *format, ...) {
   va_list ap;
   time_t t;
   struct tm *tim;
   char string[128];

   va_start(ap, format);

   if (! log_to_syslog) {
      /* not running as daemon - log to STDERR */
      time(&t);
      tim=localtime(&t);
      fprintf(stderr,"%2.2i:%2.2i:%2.2i WARNING:%s:%i ",tim->tm_hour,
                      tim->tm_min, tim->tm_sec,file,line);
      vfprintf(stderr, format, ap);
      fprintf(stderr,"\n");
   } else {
      /* running as daemon - log via SYSLOG facility */
      vsnprintf(string, sizeof(string), format, ap);
      syslog(LOG_USER|LOG_NOTICE, "%s:%i WARNING:%s", file, line, string);
   }
   
   va_end(ap);
   fflush(stderr);
   return;

}


void log_info(char *file, int line, const char *format, ...) {
   va_list ap;
   time_t t;
   struct tm *tim;
   char string[128];

   va_start(ap, format);

   if (! log_to_syslog) {
      /* not running as daemon - log to STDERR */
      time(&t);
      tim=localtime(&t);
      fprintf(stderr,"%2.2i:%2.2i:%2.2i INFO:%s:%i ",tim->tm_hour,
                      tim->tm_min, tim->tm_sec,file,line);
      vfprintf(stderr, format, ap);
      fprintf(stderr,"\n");
   } else {
      /* running as daemon - log via SYSLOG facility */
      vsnprintf(string, sizeof(string), format, ap);
      syslog(LOG_USER|LOG_NOTICE, "%s:%i INFO:%s", file, line, string);
   }
   
   va_end(ap);
   fflush(stderr);
   return;

}


void log_dump_buffer(int class, char *file, int line,
                     char *buffer, int length) {
   int i, j;
   char tmp[8], tmplin1[80], tmplin2[80];

   if ((debug_pattern & class) == 0) return;
   if (log_to_syslog) return;

   fprintf(stderr,"---BUFFER DUMP follows---\n");
/*
   for (i=0;i<length;i++) {
      fprintf(stderr,"%c",buffer[i]);
   }
*/
   for (i=0; i<length; i+=16) {
      strcpy(tmplin1,"");
      strcpy(tmplin2,"");
      for (j=0;(j<16) && (i+j)<length ;j++) {
         sprintf(tmp,"%2.2x ",(unsigned char)buffer[i+j]);
         strcat(tmplin1, tmp);
         sprintf(tmp, "%c",(isprint(buffer[i+j]))? buffer[i+j]: '.');
         strcat(tmplin2, tmp);
      }
      fprintf(stderr, "  %-47.47s %-16.16s\n",tmplin1, tmplin2);
   }

   fprintf(stderr,"\n---end of BUFFER DUMP---\n");
   fflush(stderr);
   return;
}

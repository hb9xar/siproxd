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
#include <time.h>

static char const ident[]="$Id: " __FILE__ ": " PACKAGE "-" VERSION "-"\
			  BUILDSTR " $";


int debug_pattern=0;


void log_set_pattern(int pattern) {
   debug_pattern=pattern;
}


/* for all the LOGGING routines:
   They should figure out if we are running as a daemon, then write
   their stuff to syslog or something like that
*/


void log_debug(int class, char *file, int line, const char *format, ...) {
   va_list ap;
   time_t t;
   struct tm *tim;

   if ((debug_pattern & class) == 0) return;

   va_start(ap, format);

   time(&t);
   tim=localtime(&t);
   fprintf(stderr,"%2.2i:%2.2i:%2.2i %s:%i ", tim->tm_hour,
                   tim->tm_min, tim->tm_sec, file, line);
   vfprintf(stderr, format, ap);
   fprintf(stderr,"\n");
   
   va_end(ap);
   fflush(stderr);
   return;

}


void log_error(char *file, int line, const char *format, ...) {
   va_list ap;
   time_t t;
   struct tm *tim;

   va_start(ap, format);

   time(&t);
   tim=localtime(&t);
   fprintf(stderr,"%2.2i:%2.2i:%2.2i ERROR:%s:%i ",tim->tm_hour,
                   tim->tm_min, tim->tm_sec,file,line);
   vfprintf(stderr, format, ap);
   fprintf(stderr,"\n");
   
   va_end(ap);
   fflush(stderr);
   return;

}


void log_warn(char *file, int line, const char *format, ...) {
   va_list ap;
   time_t t;
   struct tm *tim;

   va_start(ap, format);

   time(&t);
   tim=localtime(&t);
   fprintf(stderr,"%2.2i:%2.2i:%2.2i WARNING:%s:%i ",tim->tm_hour,
                   tim->tm_min, tim->tm_sec,file,line);
   vfprintf(stderr, format, ap);
   fprintf(stderr,"\n");
   
   va_end(ap);
   fflush(stderr);
   return;

}


void log_dump_buffer(int class, char *file, int line,
                     char *buffer, int length) {
   int i;

   if ((debug_pattern & class) == 0) return;

   fprintf(stderr,"---BUFFER DUMP follows---\n");
   for (i=0;i<length;i++) {
      fprintf(stderr,"%c",buffer[i]);
   }

   fprintf(stderr,"\n---end of BUFFER DUMP---\n");
   fflush(stderr);
   return;
}

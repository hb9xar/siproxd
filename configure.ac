dnl
dnl	History
dnl	-------
dnl	before time		a lot happend before start of history
dnl	 8-Sep-2002	tries	included more tests for used functions
dnl	17-Sep-2002	tries	fail configure if needed libs not there
dnl	14-Nov-2002	tries	support for *BSD systems
dnl	22-Mar-2003	tries	check for sockaddr_t, hstrerror()
dnl				--enable-almost-static (for Fli4l use)
dnl				--enable-uclibc (uClibc building support)
dnl	29-Mar-2003	tries	added support for libosip2
dnl	 6-Apr-2003	tries	redone the fli4l specific build options
dnl				now: --enable-fli4l-libc5, --enable-fli4l-uclibc
dnl	 7-Apr-2003	tries	added siproxd.spec to autoconf process
dnl	31-Jul-2003	tries	changed to support OSIP2 only
dnl	 1-Sep-2003	tries	check for IPCHAINS
dnl	 5-Sep-2003	tries	test for pthreads before libosip stuff
dnl	19-Sep-2003	tries	DMALLOC support
dnl	 1-Nov-2003	tries	check for NETFILTER (IPTABLES)
dnl	18-Nov-2003	tries	include sysconfdir to search for config
dnl	19-Nov-2003	tries	changes to support Solaris & BSD/OS
dnl	22-Nov-2003	tries	test for gethostbyname_r() & # of args
dnl	22-Jan-2004	tries	add --enable-static-exe option
dnl	06-Mar-2004	tries	del daemon(), add setsid()
dnl	09-Apr-2004	tries	add --with-custom-fwmodule
dnl	09-May-2004	tries	fli4l-uclibc links statically agains pthreads
dnl	29-May-2004	tries	use AC_CHECK_TYPE to check for socklen_t
dnl	09-May-2004	tries	fli4l-libc5 does NOT use gethostbyname_r()
dnl				(there seems to be a bug somewhere)
dnl	18-Aug-2004	tries	fli4l-uclibc -> fli4l-21-uclibc, fli4l-22-uclibc
dnl				2.1.x has no pthread support, link -static
dnl				2.2.x has (maybe) pthread support
dnl	08-Jan-2005	tries	FreeBSD: check for libgnugetopt before using it
dnl				Cygwin build support
dnl	13-Feb-2005	tries	check for # of args on libosip2 functions
dnl	10-Apr-2005	tries	check for docbook
dnl	18-Apr-2005	tries	added libresolv
dnl	 9-Oct-2005	tries	libresolv is now included in static build
dnl	10-Jun-2007	tries	test more .h files (DNS resolver related)
dnl	18-Dec-2007	tries	requires libosip2-3.x.x
dnl	02-Feb-2008	tries	removed variety of fli4l and static extra
dnl				build options
dnl	21-Feb-2009	tries	--enable-static-libosip2 does search static
dnl				libs now in libosip_prefix_dir
dnl	 1-Mar-2009	tries	building with --enable-static-libosip2 requires
dnl				--disable-shared to be set as well (plugins will
dnl				be statically linked into siproxd)
dnl	19-Feb-2010	tries	CVE-2009-3736: use libltdl on host if existing
dnl				and fall back using convenienve libltdl (WARN)
dnl	26-Apr-2010	tries	Fresh building from distribuion TAR did fail if
dnl				the host-installed libltdl lib is used (and not the
dnl				convenience lib)
dnl	09-Jan-2011	tries	use CFLAGS -Wall only with GCC compiler
dnl	15-Sep-2011	tries	added --with-included-libtool to force the
dnl				use of the included libltdl
dnl	17-Jul-2015	tries	added --with-ltdl-fix
dnl	28-May-2017	tries	going for CentOS7 as development platform,
dnl				lots of cleanup needed for autoconf (2.69),
dnl				automake (1.13.4), libtool/libltdl (2.4.2)
dnl	25-Aug-2020	tries	releae 0.8.3
dnl	17-Feb-2022	tries	add option for reproducible builds
dnl	04-Sep-2024	tries	enable subdir-objects
dnl	06-Apr-2025	tries	remoce scripts subdir from autoconf process
dnl
dnl


dnl Version Number
AC_INIT([siproxd], [0.8.4dev])

dnl Initialize autoconf / automake stuff
AC_CONFIG_SRCDIR([src/siproxd.c])
AC_CONFIG_AUX_DIR(scripts)
AC_CANONICAL_SYSTEM
AM_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([subdir-objects])


dnl
dnl Checks for needed programs.
dnl
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_CHECK_PROG(docbook2pdf,docbook2pdf,yes,)
AM_CONDITIONAL(have_docbook2pdf,test "$docbook2pdf" = "yes")
AC_CHECK_PROG(docbook2html,docbook2html,yes,)
AM_CONDITIONAL(have_docbook2html,test "$docbook2html" = "yes")


dnl **********************************************
dnl * Location of libraries / headerfiles
dnl **********************************************
dnl
dnl    --with-extra-includes
dnl    --with-extra-libs
dnl
AC_ARG_WITH(extra-includes,
   [  --with-extra-includes=DIR   adds non standard include paths],
   extra_includes="$withval" )
AC_SUBST(extra_includes)
AC_MSG_CHECKING("extra includes")
AC_MSG_RESULT($extra_includes)

AC_ARG_WITH(extra-libs,
   [  --with-extra-libs=DIR   adds non standard library paths],
   extra_libs="$withval" )
AC_SUBST(extra_libs)
AC_MSG_CHECKING("extra libs")
AC_MSG_RESULT($extra_libs)

for each in $extra_includes; do
   CPPFLAGS="$CPPFLAGS -I$each";
done

for each in $extra_libs; do
   LIBS="$LIBS -L$each";
done


dnl **********************************************
dnl prepare libtool (ltdl)
dnl **********************************************
dnl
dnl We require the ltdl (libtool portable dynamic loader)
dnl for our plugins. As this would require the automake/libtool
dnl packages to be present we optinally include that library with
dnl the siproxd package as so called "convenience library"

dnl
dnl Configure libtool
AC_PROG_LIBTOOL
LT_CONFIG_LTDL_DIR([libltdl])
LT_INIT([dlopen])
LTDL_INIT([recursive])
AC_CONFIG_FILES([libltdl/Makefile])

AC_MSG_CHECKING(using system provided libltdl)
if test yes = "$with_included_ltdl"; then
   AC_MSG_RESULT([no, using included libltdl])
   echo "*** WARNING: using convenience libltdl!";
else
   AC_MSG_RESULT([yes, using system provided libltdl])
fi


if test yes != "$with_included_ltdl"; then
AC_ARG_WITH(ltdl-fix,
   [  --with-ltdl-fix         work around broken ltdl versions (fix linking
                          error "undefined reference to lt__PROGRAM..."],
   AC_DEFINE(WITH_LTDL_FIX,,[ltdl workaround for undefined reference linking error]),
   )
fi

AC_CHECK_DECL(lt_preloaded_symbols,,[AC_DEFINE(LTDL_FIX2,,[lt_preloaded_symbols undefined])],
    [[$ac_includes_default]
    [#include <ltdl.h>]
    ]
)


dnl **********************************************
dnl * Building doc
dnl **********************************************

dnl
dnl --enable-doc
dnl

   build_docs="yes";
   AC_MSG_CHECKING(build documentation)
   AC_ARG_ENABLE(doc,
      [  --disable-doc           build pdf/html doc (default=enabled)],
      if test "x$enableval" = "xno"; then
         build_docs="no";
      fi
      AC_MSG_RESULT($build_docs), AC_MSG_RESULT($build_docs))
   if test "x$build_docs" = "xyes"; then
      AC_CHECK_PROG(docbook2pdf,docbook2pdf,yes,)
      AM_CONDITIONAL(have_docbook2pdf,test "$docbook2pdf" = "yes")
      AC_CHECK_PROG(docbook2html,docbook2html,yes,)
      AM_CONDITIONAL(have_docbook2html,test "$docbook2html" = "yes")
   else
      AM_CONDITIONAL(have_docbook2pdf,false)
      AM_CONDITIONAL(have_docbook2html,false)
   fi


dnl **********************************************
dnl * Selection of static build variants
dnl **********************************************
dnl
dnl    --enable-static-libosip2
dnl
   build_static_libosip="no"
   AC_MSG_CHECKING(link statically against libosip2)
   AC_ARG_ENABLE(static-libosip2,
      [  --enable-static-libosip2    link statically against libosip2],
      build_static_libosip="$enableval";
      AC_MSG_RESULT($enableval), AC_MSG_RESULT(no))
   if test "x$build_static_libosip" = "xyes"; then
dnl      AC_MSG_RESULT(Plugins will be linked in statically.)
dnl      enable_shared=no;
      if test "x$enable_shared" = "xyes"; then
         echo "*** ERROR: requires the '--disable-shared' option to be specified!";exit 1;
      fi
   fi


dnl **********************************************
dnl * Debugging helps
dnl **********************************************

dnl
dnl    --enable-dmalloc
dnl
   AC_MSG_CHECKING(building with DMALLOC support)
   AC_ARG_ENABLE(dmalloc,
      [  --enable-dmalloc        build with DMALLOC support],
      dmalloc="$enableval";
      AC_MSG_RESULT($enableval), AC_MSG_RESULT(no))
   if test "x$dmalloc" = "xyes"; then
      CFLAGS="$CFLAGS -DDMALLOC ";LIBS="-ldmallocth $LIBS";
   fi


dnl
dnl Use -Wall if we have gcc.
dnl
   if test "x$GCC" = "xyes"; then
      case " $CFLAGS " in
         *[\ ]-Wall[\ ]*) ;;
         *) CFLAGS="$CFLAGS -Wall" ;;
      esac
   fi


dnl
dnl target platform specific stuff
dnl
AC_DEFINE_UNQUOTED(UNAME,"$target",[target platform])
AC_MSG_CHECKING(target platform)
case "$target" in
  *-*-linux*)
    AC_MSG_RESULT(Linux)
    AC_DEFINE(_LINUX,,[building on Linux platform])
    ;;
  *-*-freebsd*)
    AC_MSG_RESULT(FreeBSD)
    AC_DEFINE(_BSD,,[building on BSD platform])
    AC_DEFINE(_FREEBSD,,[building on FreeBSD platform])
    CPPFLAGS="$CPPFLAGS -I/usr/local/include/"
    LIBS="$LIBS -L/usr/local/lib/"
    AC_CHECK_LIB(gnugetopt,getopt_long,[LIBS="$LIBS -lgnugetopt"])
    ;;
  *-*-openbsd*)
    AC_MSG_RESULT(OpenBSD)
    AC_DEFINE(_BSD,,[building on BSD platform])
    AC_DEFINE(_OPENBSD,,[building on OpenBSD platform])
    CPPFLAGS="$CPPFLAGS -I/usr/local/include/"
    LIBS="$LIBS -L/usr/local/lib/"
    ;;
  *-*-netbsd*)
    AC_MSG_RESULT(NetBSD)
    AC_DEFINE(_BSD,,[building on BSD platform])
    AC_DEFINE(_NETBSD,,[building on NetBSD platform])
    CPPFLAGS="$CPPFLAGS -I/usr/pkg/include"
    LIBS="$LIBS -L/usr/pkg/lib"
    ;;
  *-*-bsdi* | *-*-bsdos*)
    AC_MSG_RESULT(BSD/OS)
    AC_DEFINE(_BSD,,[building on BSD platform])
    AC_DEFINE(_BSDOS,,[building on BSD/OS platform])
    ;;
  *-*-solaris2*)
    # It's easier to do this here, rather than AC_CHECK_LIBS for all of the
    # things that are/might be in libsocket or libnsl...
    AC_MSG_RESULT(Solaris 2.x)
    AC_DEFINE(_SOLARIS2,,[building on Solaris2 platform])
    LIBS="$LIBS -lsocket -lnsl"
    ;;
  *-*-darwin*)
    AC_MSG_RESULT(Mac OS X)
    AC_DEFINE(_MACOSX,,[building on Mac OSX platform])
    ;;
  *-*-cygwin*)
    AC_MSG_RESULT(Cygwin)
    AC_DEFINE(_CYGWIN,,[building on Cygwin (Windows) platform])
    ;;
  *)
    AC_MSG_RESULT(Unknown Platform)
    AC_DEFINE(_UNKNOWN,,[building on unknown platform])
    ;;
esac


dnl
dnl Check for pthreads
dnl
ACX_PTHREAD(,
   echo "*** ERROR: pthreads is required!"; exit 1;)
   dnl link dynamically (default)
   LIBS="$PTHREAD_LIBS $LIBS"
   CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
   LDFLAGS="$LDFLAGS $PTHREAD_LDFLAGS"
   CC="$PTHREAD_CC"


dnl
dnl Make sure that symbol _POSIX_THREAD_SAFE_FUNCTIONS is defined.
dnl This is needed by some platforms to make reentrant functions
dnl available (gethostbyname_r)
dnl
CFLAGS="$CFLAGS -D_POSIX_THREAD_SAFE_FUNCTIONS"


dnl
dnl add
dnl    --with-libosip-prefix=DIR
dnl
libosip_prefix_dir=""
AC_ARG_WITH(libosip-prefix,
   [  --with-libosip-prefix=DIR   use libosip2 from DIR/include and DIR/lib],
   if test x$withval != x ; then libosip_prefix_dir="$withval"; fi,
   )
AC_SUBST(libosip_prefix_dir)
AC_MSG_CHECKING("libosip prefix")
AC_MSG_RESULT($libosip_prefix_dir)


dnl
dnl Check for libosip
dnl
if test x$libosip_prefix_dir != x; then
   LIBS="-L$libosip_prefix_dir/lib $LIBS"
   CPPFLAGS="$CPPFLAGS -I$libosip_prefix_dir/include"
fi

dnl
dnl Static or dynamic linking against libosip
dnl
if test "x$build_static_libosip" = "xno"; then
   dnl link dynamically (default)
   AC_CHECK_LIB(osip2, osip_init,,
      echo "*** ERROR: libosip2 is required!  "\
            "Maybe you need to use --with-libosip-prefix ?"; exit 1;,
      [-losipparser2])
   AC_CHECK_LIB(osipparser2, parser_init,,
      echo "*** ERROR: libosipparser2 is required!";exit 1;,)
else
   dnl link statically to this lib
   dnl (this probably only will work on linux yet...)
   AC_MSG_CHECKING("where I can find libosip2.a")
   libosip_static=`find $extra_libs $libosip_prefix_dir/lib /lib \
                        /usr/lib /usr/local/lib \
                        -name libosip2.a 2>/dev/null|head -1`
   if test "x$libosip_static" != "x"; then
      LIBS="$libosip_static $LIBS"
      AC_MSG_RESULT($libosip_static)
   else
      echo "*** ERROR: a static libosip library is required!";exit 1;
   fi
   AC_MSG_CHECKING("where I can find libosipparser2.a")
   libosip_static=`find $extra_libs $libosip_prefix_dir/lib /lib \
                        /usr/lib /usr/local/lib \
                        -name libosipparser2.a 2>/dev/null|head -1`
   if test "x$libosip_static" != "x"; then
      LIBS="$libosip_static $LIBS"
      AC_MSG_RESULT($libosip_static)
   else
      echo "*** ERROR: a static libosip library is required!";exit 1;
   fi
fi

dnl
dnl correct version of libosip2?
dnl
ACX_CHECK_LIBOSIP_VERSION()


dnl
dnl add
dnl    --with-custom-fwmodule
   AC_MSG_CHECKING(building with a custom FW module)
   AC_ARG_WITH(custom-fwmodule,
      [  --with-custom-fwmodule=LIBRARY.a   use custom firewall control module],
      FWLIBS="$withval";
      AC_DEFINE(CUSTOM_FWMODULE, 1,[use custom firewall control module])
      AC_MSG_RESULT($FWLIBS), AC_MSG_RESULT(no))


dnl
dnl reproducible-build:
dnl SOURCE_DATE_EPOCH defined, or --enable-reproducible-build given
dnl
   reproducible_build="no"
   dnl check SOURCE_DATE_EPOCH
   AC_MSG_CHECKING(whether we have SOURCE_DATE_EPOCH defined)
   if test "x$SOURCE_DATE_EPOCH" != "x"; then
     AC_SUBST(SOURCE_DATE_EPOCH, $SOURCE_DATE_EPOCH)
     AC_MSG_RESULT(yes)
   else
     AC_MSG_RESULT(no)
   fi
   AM_CONDITIONAL(HAVE_SOURCE_DATE_EPOCH, test "x$SOURCE_DATE_EPOCH" != "x")

   dnl check --enable-reproducible-build
   AC_MSG_CHECKING(whether to enable a reproducible build)
   AC_ARG_ENABLE(reproducible-build,
      [  --enable-reproducible-build
                          enable reproducible build (default is no)],
      [  if test "x$enableval" = "xyes"; then
           reproducible_build="yes"
         fi
      ]
   )
   AC_MSG_RESULT($reproducible_build)
   AM_CONDITIONAL(REPRODUCIBLE_BUILD, test "x$reproducible_build" = "xyes")

dnl
dnl Checks for header files.
dnl
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/time.h errno.h)
AC_CHECK_HEADERS(stdarg.h varargs.h)
AC_CHECK_HEADERS(pwd.h getopt.h sys/socket.h netdb.h)
AC_CHECK_HEADERS(resolv.h arpa/nameser.h)


dnl
dnl Checks for typedefs, structures, and compiler characteristics.
dnl
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM


dnl
dnl Check for Constants that may be non-existing on some platforms
dnl
dnl SOL_IP (used in setsockopt)
AC_CHECK_DECL(SOL_IP,
    ,
    AC_MSG_RESULT(SOL_IP is not available - creating DEFINE to IPPROTO_IP)
    AC_DEFINE(SOL_IP,IPPROTO_IP,[SOL_IP for setsockopt()]),
    [[$ac_includes_default]
    [#ifdef HAVE_NETDB_H]
    [#include <netdb.h>]
    [#endif]
    [#ifdef HAVE_SYS_SOCKET_H]
    [#include <sys/socket.h>]
    [#endif]
    ]
)


dnl
dnl check for typedef socklen (not available on SUSE 5.3 for example)
dnl
dnl  FreeBSD has it in <netdb.h> and <sys/socket.h>
AC_CHECK_TYPE(socklen_t,
    ,
    AC_MSG_RESULT(socklen_t is not available - creating DEFINE to uint)
    AC_DEFINE(socklen_t, [unsigned int],[typedef socklen_t available]),
    [[$ac_includes_default]
    [#ifdef HAVE_NETDB_H]
    [#include <netdb.h>]
    [#endif]
    [#ifdef HAVE_SYS_SOCKET_H]
    [#include <sys/socket.h>]
    [#endif]
    ]
)


dnl
dnl Checks for libraries
dnl Note: the __res_query symbol is to catch the lib when building "static"
dnl
    AC_CHECK_LIB(resolv,res_query,)	dnl found only in static lib
    AC_CHECK_LIB(resolv,__res_query,)	dnl found in static and dynamic lib


dnl
dnl Checks for library functions.
dnl

AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(strerror)

AC_CHECK_FUNCS(gethostbyname)

dnl !! with FLI4L 2.0.x strange behavior with gethostbyname_r()
dnl !! has been seen, dont use it. the ACX_WHICH_GETHOSTBYNAME_R
dnl !! shall then be commented out.
ACX_WHICH_GETHOSTBYNAME_R()

AC_CHECK_FUNCS(getopt_long setsid syslog)
AC_CHECK_FUNCS(getuid setuid getgid setgid getpwnam chroot)
AC_CHECK_FUNCS(socket bind select read send sendto fcntl)
AC_CHECK_FUNCS(getifaddrs)
AC_CHECK_FUNCS(strcmp strcasecmp)
AC_CHECK_FUNCS(strncpy strchr strstr sprintf vfprintf vsnprintf)
AC_CHECK_FUNCS(listen accept)
AC_CHECK_FUNCS(fgets sscanf)
AC_CHECK_FUNCS(hstrerror,,AC_CHECK_LIB(resolv,hstrerror,[
	       AC_DEFINE_UNQUOTED(HAVE_HSTRERROR)
	       LIBS="$LIBS -lresolv"]))
AC_CHECK_FUNCS(inet_pton inet_ntop inet_aton inet_ntoa)
AC_CHECK_FUNCS(pthread_setschedparam sched_get_priority_min)
AC_CHECK_FUNCS(sched_get_priority_max)
AC_CHECK_FUNCS(lt_dlopen lt_dlsym lt_dlclose)


dnl
dnl sysconfdir
dnl
SIPROXDCONFPATH=""
tmpset="$sysconfdir"
while test "x$tmpset" != "x$SIPROXDCONFPATH"; do
  SIPROXDCONFPATH="$tmpset"
  eval tmpset="$tmpset"
done
AC_DEFINE_UNQUOTED(SIPROXDCONFPATH,"$SIPROXDCONFPATH",
                  [will search for config file here])


dnl
dnl Finish...
dnl
LIBS="$LIBS $FWLIBS"

AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(LIBS)


dnl
dnl Generate output files
dnl
AC_OUTPUT( \
siproxd.spec \
Makefile \
src/Makefile \
doc/Makefile \
contrib/Makefile \
)

AC_INIT([onvif_tool], [0.1], [anton@corp.bluecherry.net], [https://github.com/bluecherrydvr/onvif_tool])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AC_PROG_CXX

AC_PATH_PROG([WSDL2H],[wsdl2h])
AC_PATH_PROG([SOAPCPP2],[soapcpp2])

PKG_CHECK_MODULES([GSOAPSSL], [gsoapssl++], HAVE_GSOAPSSL=yes, AC_MSG_ERROR(["gsoapssl library not found"]))
PKG_CHECK_VAR([GSOAP_PREFIX], [gsoap], [prefix])
AS_IF([test "x$GSOAP_PREFIX" = "x"], [
  AC_MSG_FAILURE([Unable to identify gsoap prefix path.])
])

AC_CHECK_LIB(z, inflateEnd, [], [AC_MSG_ERROR("zlib not found")])
AC_CHECK_LIB([crypto], [RAND_add],[],[AC_MSG_ERROR(["libcrypto from OpenSSL package not found"])],[ -lz ])
AC_CHECK_LIB([ssl], [SSL_new],[],[AC_MSG_ERROR(["libssl from OpenSSL package not found"])])


AC_OUTPUT([Makefile])


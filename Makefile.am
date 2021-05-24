bin_PROGRAMS = onvif_tool

CLEANFILES = soap*.cpp wsdd*.cpp onvif.h soap*.h wsdd*.h *.nsmap

onvif_tool_SOURCES = main.cpp

BUILT_SOURCES = generated_sources onvif.h

onvif_tool_CPPFLAGS = -I. -I $(GSOAP_PREFIX)/include -I $(GSOAP_PREFIX)/share/gsoap/plugin -I $(GSOAP_PREFIX)/share/gsoap/custom -I $(GSOAP_PREFIX)/prefix/share/gsoap -I $(GSOAP_PREFIX)/share/gsoap
onvif_tool_CXXFLAGs = -std=c++11 $(GSOAPSSL_CFLAGS)
onvif_tool_CFLAGS = -x c++ $(GSOAPSSL_CFLAGS)
onvif_tool_LDADD = $(GSOAPSSL_LIBS)

nodist_onvif_tool_SOURCES = \
soapC.cpp  \
wsddClient.cpp \
wsddServer.cpp \
soapAdvancedSecurityServiceBindingProxy.cpp \
soapDeviceBindingProxy.cpp \
soapDeviceIOBindingProxy.cpp \
soapImagingBindingProxy.cpp \
soapMediaBindingProxy.cpp \
soapPTZBindingProxy.cpp \
soapPullPointSubscriptionBindingProxy.cpp \
soapRemoteDiscoveryBindingProxy.cpp \
$(GSOAP_PREFIX)/share/gsoap/plugin/smdevp.c \
$(GSOAP_PREFIX)/share/gsoap/plugin/mecevp.c \
$(GSOAP_PREFIX)/share/gsoap/plugin/wsaapi.c \
$(GSOAP_PREFIX)/share/gsoap/plugin/wsseapi.c \
$(GSOAP_PREFIX)/share/gsoap/plugin/wsddapi.c \
$(GSOAP_PREFIX)/share/gsoap/custom/struct_timeval.c

nodist_onvif_tool_SOURCES +=  onvif.h

WSDL_URLS = \
http://www.onvif.org/onvif/ver10/device/wsdl/devicemgmt.wsdl \
http://www.onvif.org/onvif/ver10/events/wsdl/event.wsdl \
http://www.onvif.org/onvif/ver10/deviceio.wsdl \
https://www.onvif.org/ver20/analytics/wsdl/analytics.wsdl \
http://www.onvif.org/onvif/ver20/imaging/wsdl/imaging.wsdl \
http://www.onvif.org/onvif/ver10/media/wsdl/media.wsdl \
http://www.onvif.org/onvif/ver20/ptz/wsdl/ptz.wsdl \
http://www.onvif.org/onvif/ver10/network/wsdl/remotediscovery.wsdl \
http://www.onvif.org/ver10/advancedsecurity/wsdl/advancedsecurity.wsdl

onvif.h: Makefile onvif.h.patch
	wsdl2h -d -O4 -P   -o $@   $(WSDL_URLS)
	patch -p1 < onvif.h.patch

generated_sources: onvif.h
	soapcpp2 -2 -C -I $(GSOAP_PREFIX)/share/gsoap/import -I $(GSOAP_PREFIX)/share/gsoap -I $(GSOAP_PREFIX)/share/gsoap/custom -j -x onvif.h
	soapcpp2 -a -x -L -pwsdd -I $(GSOAP_PREFIX)/share/gsoap/import/ $(GSOAP_PREFIX)/share/gsoap/import/wsdd5.h


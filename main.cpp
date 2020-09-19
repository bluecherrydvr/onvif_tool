/*
 * Copyright (c) 2020 Bluecherry, LLC
 * Copyrigh (c) 2020 Anton Sviridenko
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "soapDeviceBindingProxy.h"
#include "soapMediaBindingProxy.h"
#include "soapPTZBindingProxy.h"
#include "soapPullPointSubscriptionBindingProxy.h"
#include "soapRemoteDiscoveryBindingProxy.h"
#include "plugin/wsddapi.h"
#include "plugin/wsseapi.h"
#include "wsdd.nsmap"

#include <regex>
#include <iostream>
#include <string>

static char *g_username;
static char *g_password;
static char *g_hostname;

// #define PROTECT

#ifdef PROTECT
// define some global data that is set once, to keep this example simple
EVP_PKEY *privk = NULL;
X509 *cert = NULL;
#endif

int CRYPTO_thread_setup();
void CRYPTO_thread_cleanup();

// to report an error
void report_error(struct soap *soap)
{
	std::cerr << "Oops, something went wrong:" << std::endl;
	soap_stream_fault(soap, std::cerr);
	exit(EXIT_FAILURE);
}

static void set_device_endpoint(DeviceBindingProxy *dev, const char *hostname)
{
	static char soap_endpoint[1024];
	sprintf(soap_endpoint, "http://%s/onvif/device_service", hostname);

	dev->soap_endpoint = soap_endpoint;
}

// to set the timestamp and authentication credentials in a request message
void set_credentials(struct soap *soap)
{
	soap_wsse_delete_Security(soap);
	if (soap_wsse_add_Timestamp(soap, "Time", 10)
	        || soap_wsse_add_UsernameTokenDigest(soap, "Auth", g_username, g_password))
		report_error(soap);
#ifdef PROTECT
	if (!privk)
	{
		FILE *fd = fopen("client.pem";
		if (fd)
		{
			privk = PEM_read_PrivateKey(fd, NULL, NULL, (void*)"password");
			fclose(fd);
		}
		if (!privk)
		{
			fprintf(stderr, "Could not read private key from client.pem\n");
			exit(EXIT_FAILURE);
		}
	}
	if (!cert)
	{
		FILE *fd = fopen("clientcert.pem", "r");
		if (fd)
		{
			cert = PEM_read_X509(fd, NULL, NULL, NULL);
			fclose(fd);
		}
		if (!cert)
		{
			fprintf(stderr, "Could not read certificate from clientcert.pem\n");
			exit(EXIT_FAILURE);
		}
	}
	if (soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert)
	        || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token")
	        || soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA256, rsa_privk, 0)
	        || soap_wsse_verify_auto(soap, SOAP_SMD_NONE, NULL, 0))
		report_error(soap);
#endif
}

// to check if an ONVIF service response was signed with WS-Security (when enabled)
void check_response(struct soap *soap)
{
#ifdef PROTECT
	// check if the server returned a signed message body, if not error
	if (soap_wsse_verify_body(soap))
		report_error(soap);
	soap_wsse_delete_Security(soap);
#endif
}

int skip_unknown(struct soap *soap, const char *tag)
{
	//std::cerr << "unknown tag: " << tag << std::endl;
	return SOAP_OK;
}

// to download a snapshot and save it locally in the current dir as image-1.jpg, image-2.jpg, image-3.jpg ...
void save_snapshot(int i, const char *endpoint)
{
	char filename[32];
	(SOAP_SNPRINTF_SAFE(filename, 32), "image-%d.jpg", i);
	FILE *fd = fopen(filename, "wb");
	if (!fd)
	{
		std::cerr << "Cannot open " << filename << " for writing" << std::endl;
		exit(EXIT_FAILURE);
	}

	// create a temporary context to retrieve the image with HTTP GET
	struct soap *soap = soap_new();
	soap->fignore = skip_unknown;
	soap->connect_timeout = soap->recv_timeout = soap->send_timeout = 10; // 10 sec

	if (soap_ssl_client_context(soap, SOAP_SSL_DEFAULT | SOAP_SSL_SKIP_HOST_CHECK, NULL, NULL, NULL, "/etc/ssl/certs", NULL))
		report_error(soap);

	std::cout << "GET" << std::endl;
	// HTTP GET and save image
	if (soap_GET(soap, endpoint, NULL) || soap_begin_recv(soap))
	{
		std::cout << "Auth realm " << soap->authrealm << " HTTP status code" << soap->status << std::endl;

		if (soap->authrealm)
		{
			//try HTTP auth
			soap->userid = g_username;
			soap->passwd = g_password;
			if (soap_GET(soap, endpoint, NULL) || soap_begin_recv(soap))
				report_error(soap);
		}
		else
			report_error(soap);
	}

//  if (soap_begin_recv(soap))
//    report_error(soap);
//  	std::cout << "Snapshot request failure" << std::endl;

	std::cout << "Retrieving " << filename;
	if (soap->http_content)
		std::cout << " of type " << soap->http_content;
	std::cout << " from " << endpoint << std::endl;

	// this example stores the whole image in memory first, before saving it to the file
	// better is to copy the source code of soap_http_get_body here and
	// modify it to save data directly to the file.
	size_t imagelen;
	char *image = soap_http_get_body(soap, &imagelen); // NOTE: soap_http_get_body was renamed from soap_get_http_body in gSOAP 2.8.73
	soap_end_recv(soap);
	fwrite(image, 1, imagelen, fd);

	//cleanup
	fclose(fd);
	soap_destroy(soap);
	soap_end(soap);
	soap_free(soap);
}

void events_unsubscribe(struct soap *soap, const char *subscription_endpoint)
{
	PullPointSubscriptionBindingProxy proxyEvent(soap);

	_wsnt__Unsubscribe Unsubscribe;
	_wsnt__UnsubscribeResponse UnsubscribeResponse;
	proxyEvent.soap_endpoint = subscription_endpoint;
	set_credentials(soap);
	if (proxyEvent.Unsubscribe(&Unsubscribe, UnsubscribeResponse))
		report_error(soap);
	check_response(soap);

	std::cout << "OK" << std::endl;
}

void events_subscribe(struct soap *soap)
{
	DeviceBindingProxy proxyDevice(soap);
	PullPointSubscriptionBindingProxy proxyEvent(soap);

	set_device_endpoint(&proxyDevice, g_hostname);

	_tds__GetCapabilities GetCapabilities;
	_tds__GetCapabilitiesResponse GetCapabilitiesResponse;
	set_credentials(soap);
	if (proxyDevice.GetCapabilities(&GetCapabilities, GetCapabilitiesResponse))
		report_error(soap);
	check_response(soap);
	if (!GetCapabilitiesResponse.Capabilities || !GetCapabilitiesResponse.Capabilities->Events)
	{
		std::cerr << "Missing device capabilities info" << std::endl;
		exit(EXIT_FAILURE);
	}

	// set the Event proxy endpoint to XAddr
	proxyEvent.soap_endpoint = GetCapabilitiesResponse.Capabilities->Events->XAddr.c_str();
	//std::cout << GetCapabilitiesResponse.Capabilities->Events->XAddr << std::endl;
	/*
	_tev__GetEventProperties GetEventProperties;
	_tev__GetEventPropertiesResponse GetEventPropertiesResponse;

	set_credentials(soap);
	if (proxyEvent.GetEventProperties(&GetEventProperties, GetEventPropertiesResponse))
		report_error(soap);
	check_response(soap);

	//GetEventPropertiesResponse.wstop__TopicSet->soap_put(soap, NULL, NULL);
	soap_write__tev__GetEventPropertiesResponse(soap, &GetEventPropertiesResponse);
	std::cout << std::endl;
	soap_write_wstop__TopicSetType(soap, GetEventPropertiesResponse.wstop__TopicSet);
	std::cout << std::endl;

	for (unsigned int i = 0; i < GetEventPropertiesResponse.TopicNamespaceLocation.size(); i++)
	{
		std::cout << GetEventPropertiesResponse.TopicNamespaceLocation[i] << std::endl;
	}

	std::cout << std::endl;

	for (unsigned int i = 0; i < GetEventPropertiesResponse.wsnt__TopicExpressionDialect.size(); i++)
	{
		std::cout << GetEventPropertiesResponse.wsnt__TopicExpressionDialect[i] << std::endl;
	}

	std::cout << std::endl;

	for (unsigned int i = 0; i < GetEventPropertiesResponse.MessageContentFilterDialect.size(); i++)
	{
		std::cout << GetEventPropertiesResponse.MessageContentFilterDialect[i] << std::endl;
	}

	std::cout << std::endl;

	for (unsigned int i = 0; i < GetEventPropertiesResponse.ProducerPropertiesFilterDialect.size(); i++)
	{
		std::cout << GetEventPropertiesResponse.ProducerPropertiesFilterDialect[i] << std::endl;
	}

	std::cout << std::endl;

	for (unsigned int i = 0; i < GetEventPropertiesResponse.MessageContentSchemaLocation.size(); i++)
	{
		std::cout << GetEventPropertiesResponse.MessageContentSchemaLocation[i] << std::endl;
	}*/

	//subscribe to events
	_tev__CreatePullPointSubscription CreatePullPointSubscription;
	_tev__CreatePullPointSubscriptionResponse CreatePullPointSubscriptionResponse;

	set_credentials(soap);
	if (proxyEvent.CreatePullPointSubscription(&CreatePullPointSubscription, CreatePullPointSubscriptionResponse))
		report_error(soap);
	check_response(soap);

	std::cout << CreatePullPointSubscriptionResponse.SubscriptionReference.Address << std::endl;

	_tev__PullMessages PullMessages;
	_tev__PullMessagesResponse PullMessagesResponse;
	do
	{
		PullMessages.Timeout = "PT8S";
		PullMessages.MessageLimit = 10;
		proxyEvent.soap_endpoint = CreatePullPointSubscriptionResponse.SubscriptionReference.Address;
		set_credentials(soap);
		if (proxyEvent.PullMessages(&PullMessages, PullMessagesResponse))
			report_error(soap);
		check_response(soap);

		for (unsigned int i = 0; i < PullMessagesResponse.wsnt__NotificationMessage.size(); i++)
		{
			soap_dom_element *dom;
			int skip = 0;

			dom = &PullMessagesResponse.wsnt__NotificationMessage[i]->Message.__any;
			if (dom)
				for (xsd__anyType::iterator it = dom->find("@*:Name"); it != dom->end(); ++it)
					if (strcmp(it->att_get("*:Name")->get_text(), "IsMotion") == 0 && it->att_get("*:Value")->is_false())
					{
						skip = 1;
						break;
					}

			if (skip)
				continue;

			dom = &PullMessagesResponse.wsnt__NotificationMessage[i]->Topic->__mixed;
				std::cout << "ONVIF event topic: " << dom->get_text() << std::endl;
		}
	}
	while(/*PullMessagesResponse.wsnt__NotificationMessage.size() > 0*/ 1);

}

void show_resolutions(struct soap *soap)
{
	DeviceBindingProxy proxyDevice(soap);
	MediaBindingProxy proxyMedia(soap);

	set_device_endpoint(&proxyDevice, g_hostname);

	_tds__GetCapabilities GetCapabilities;
	_tds__GetCapabilitiesResponse GetCapabilitiesResponse;
	set_credentials(soap);
	if (proxyDevice.GetCapabilities(&GetCapabilities, GetCapabilitiesResponse))
		report_error(soap);
	check_response(soap);
	if (!GetCapabilitiesResponse.Capabilities || !GetCapabilitiesResponse.Capabilities->Media)
	{
		std::cerr << "Missing device capabilities info" << std::endl;
		exit(EXIT_FAILURE);
	}

	// set the Media proxy endpoint to XAddr
	proxyMedia.soap_endpoint = GetCapabilitiesResponse.Capabilities->Media->XAddr.c_str();

	_trt__GetVideoEncoderConfigurationOptions GetVideoEncoderConfigurationOptions;
	_trt__GetVideoEncoderConfigurationOptionsResponse GetVideoEncoderConfigurationOptionsResponse;

	set_credentials(soap);
	if (proxyMedia.GetVideoEncoderConfigurationOptions(&GetVideoEncoderConfigurationOptions, GetVideoEncoderConfigurationOptionsResponse))
		report_error(soap);
	check_response(soap);

	if (!GetVideoEncoderConfigurationOptionsResponse.Options)
	{
		std::cerr << "Missing device capabilities info" << std::endl;
		exit(EXIT_FAILURE);
	}

	if (GetVideoEncoderConfigurationOptionsResponse.Options->H264)
	{
		for (unsigned long i = 0; i < GetVideoEncoderConfigurationOptionsResponse.Options->H264->ResolutionsAvailable.size(); i++)
			std::cout << GetVideoEncoderConfigurationOptionsResponse.Options->H264->ResolutionsAvailable[i]->Width
					<< "x"
					<< GetVideoEncoderConfigurationOptionsResponse.Options->H264->ResolutionsAvailable[i]->Height
					<< std::endl;
	}
	else if (GetVideoEncoderConfigurationOptionsResponse.Options->JPEG)
	{
		for (unsigned long i = 0; i < GetVideoEncoderConfigurationOptionsResponse.Options->JPEG->ResolutionsAvailable.size(); i++)
			std::cout << GetVideoEncoderConfigurationOptionsResponse.Options->JPEG->ResolutionsAvailable[i]->Width
					<< "x"
					<< GetVideoEncoderConfigurationOptionsResponse.Options->JPEG->ResolutionsAvailable[i]->Height
					<< std::endl;
	}
}

void set_resolution(struct soap *soap, char *res)
{
	int w, h;
	DeviceBindingProxy proxyDevice(soap);
	MediaBindingProxy proxyMedia(soap);

	set_device_endpoint(&proxyDevice, g_hostname);

	_tds__GetCapabilities GetCapabilities;
	_tds__GetCapabilitiesResponse GetCapabilitiesResponse;
	set_credentials(soap);
	if (proxyDevice.GetCapabilities(&GetCapabilities, GetCapabilitiesResponse))
		report_error(soap);
	check_response(soap);
	if (!GetCapabilitiesResponse.Capabilities || !GetCapabilitiesResponse.Capabilities->Media)
	{
		std::cerr << "Missing device capabilities info" << std::endl;
		exit(EXIT_FAILURE);
	}

	// set the Media proxy endpoint to XAddr
	proxyMedia.soap_endpoint = GetCapabilitiesResponse.Capabilities->Media->XAddr.c_str();

	w = atoi(strtok(res, "x"));
	h = atoi(strtok(NULL, "x"));

	printf("%ux%u\n", w,h);

	_trt__GetVideoEncoderConfigurations GetVideoEncoderConfigurations;
	_trt__GetVideoEncoderConfigurationsResponse GetVideoEncoderConfigurationsResponse;

	set_credentials(soap);
	if (proxyMedia.GetVideoEncoderConfigurations(&GetVideoEncoderConfigurations, GetVideoEncoderConfigurationsResponse))
		report_error(soap);
	check_response(soap);

	_trt__SetVideoEncoderConfiguration SetVideoEncoderConfiguration;
	_trt__SetVideoEncoderConfigurationResponse SetVideoEncoderConfigurationResponse;

	SetVideoEncoderConfiguration.Configuration = GetVideoEncoderConfigurationsResponse.Configurations[0];
	SetVideoEncoderConfiguration.Configuration->Resolution->Width = w;
	SetVideoEncoderConfiguration.Configuration->Resolution->Height = h;

	set_credentials(soap);
	if (proxyMedia.SetVideoEncoderConfiguration(&SetVideoEncoderConfiguration, SetVideoEncoderConfigurationResponse))
		report_error(soap);
	check_response(soap);

	puts("OK");
}

void get_stream_urls(struct soap *soap)
{

	DeviceBindingProxy proxyDevice(soap);
	MediaBindingProxy proxyMedia(soap);

	// get device info and print
	//proxyDevice.soap_endpoint = soap_endpoint;
	set_device_endpoint(&proxyDevice, g_hostname);

	_tds__GetCapabilities GetCapabilities;
	_tds__GetCapabilitiesResponse GetCapabilitiesResponse;
	set_credentials(soap);
	if (proxyDevice.GetCapabilities(&GetCapabilities, GetCapabilitiesResponse))
		report_error(soap);
	check_response(soap);
	if (!GetCapabilitiesResponse.Capabilities || !GetCapabilitiesResponse.Capabilities->Media)
	{
		std::cerr << "Missing device capabilities info" << std::endl;
		exit(EXIT_FAILURE);
	}

	// set the Media proxy endpoint to XAddr
	proxyMedia.soap_endpoint = GetCapabilitiesResponse.Capabilities->Media->XAddr.c_str();
	//proxyMedia.soap_endpoint = "http://201.0.143.16:8089/onvif/media_service";

	std::cout << GetCapabilitiesResponse.Capabilities->Media->XAddr << std::endl;

	// get device profiles
	_trt__GetProfiles GetProfiles;
	_trt__GetProfilesResponse GetProfilesResponse;
	set_credentials(soap);
	if (proxyMedia.GetProfiles(&GetProfiles, GetProfilesResponse))
		report_error(soap);
	check_response(soap);

	for (unsigned long i = 0; i < GetProfilesResponse.Profiles.size(); ++i)
	{
		_trt__GetStreamUri GetStreamUri;
		_trt__GetStreamUriResponse GetStreamUriResponse;

		GetStreamUri.ProfileToken = GetProfilesResponse.Profiles[i]->token;
		GetStreamUri.StreamSetup = soap_new_tt__StreamSetup(soap);
		GetStreamUri.StreamSetup->Stream = tt__StreamType__RTP_Unicast;
		GetStreamUri.StreamSetup->Transport = soap_new_tt__Transport(soap);
		GetStreamUri.StreamSetup->Transport->Protocol = tt__TransportProtocol__TCP;
		set_credentials(soap);
		if (proxyMedia.GetStreamUri(&GetStreamUri, GetStreamUriResponse))
			report_error(soap);
		check_response(soap);

		if (GetStreamUriResponse.MediaUri)
			std::cout << GetStreamUriResponse.MediaUri->Uri << std::endl;
	}

}

void show_info(struct soap *soap)
{
	// create the proxies to access the ONVIF service API at HOSTNAME
	DeviceBindingProxy proxyDevice(soap);
	MediaBindingProxy proxyMedia(soap);

	// get device info and print
	//proxyDevice.soap_endpoint = soap_endpoint;
	set_device_endpoint(&proxyDevice, g_hostname);

	_tds__GetDeviceInformation GetDeviceInformation;
	_tds__GetDeviceInformationResponse GetDeviceInformationResponse;
	set_credentials(soap);
	if (proxyDevice.GetDeviceInformation(&GetDeviceInformation, GetDeviceInformationResponse))
		report_error(soap);
	check_response(soap);
	std::cout << "Manufacturer:    " << GetDeviceInformationResponse.Manufacturer << std::endl;
	std::cout << "Model:           " << GetDeviceInformationResponse.Model << std::endl;
	std::cout << "FirmwareVersion: " << GetDeviceInformationResponse.FirmwareVersion << std::endl;
	std::cout << "SerialNumber:    " << GetDeviceInformationResponse.SerialNumber << std::endl;
	std::cout << "HardwareId:      " << GetDeviceInformationResponse.HardwareId << std::endl;

	// get device capabilities and print media
	_tds__GetCapabilities GetCapabilities;
	_tds__GetCapabilitiesResponse GetCapabilitiesResponse;
	set_credentials(soap);
	if (proxyDevice.GetCapabilities(&GetCapabilities, GetCapabilitiesResponse))
		report_error(soap);
	check_response(soap);
	if (!GetCapabilitiesResponse.Capabilities || !GetCapabilitiesResponse.Capabilities->Media)
	{
		std::cerr << "Missing device capabilities info" << std::endl;
		exit(EXIT_FAILURE);
	}
	std::cout << "XAddr:        " << GetCapabilitiesResponse.Capabilities->Media->XAddr << std::endl;
	if (GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities)
	{
		if (GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTPMulticast)
			std::cout << "RTPMulticast: " << (*GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTPMulticast ? "yes" : "no") << std::endl;
		if (GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTP_USCORETCP)
			std::cout << "RTP_TCP:      " << (*GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTP_USCORETCP ? "yes" : "no") << std::endl;
		if (GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTP_USCORERTSP_USCORETCP)
			std::cout << "RTP_RTSP_TCP: " << (*GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTP_USCORERTSP_USCORETCP ? "yes" : "no") << std::endl;
	}

	// set the Media proxy endpoint to XAddr
	proxyMedia.soap_endpoint = GetCapabilitiesResponse.Capabilities->Media->XAddr.c_str();

	// get device profiles
	_trt__GetProfiles GetProfiles;
	_trt__GetProfilesResponse GetProfilesResponse;
	set_credentials(soap);
	if (proxyMedia.GetProfiles(&GetProfiles, GetProfilesResponse))
		report_error(soap);
	check_response(soap);

	//print resolutions
	// for each profile get snapshot
	for (unsigned long i = 0; i < GetProfilesResponse.Profiles.size(); ++i)
	{
		std::cout << "Resolution: "
		<< GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->Resolution->Width
		<< "x"
		<< GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->Resolution->Height
		<< std::endl;
		// get snapshot URI for profile
		_trt__GetSnapshotUri GetSnapshotUri;
		_trt__GetSnapshotUriResponse GetSnapshotUriResponse;
		GetSnapshotUri.ProfileToken = GetProfilesResponse.Profiles[i]->token;
		set_credentials(soap);
		if (proxyMedia.GetSnapshotUri(&GetSnapshotUri, GetSnapshotUriResponse))
			report_error(soap);
		check_response(soap);
		std::cout << "Profile name: " << GetProfilesResponse.Profiles[i]->Name << std::endl;
		if (GetSnapshotUriResponse.MediaUri)
			save_snapshot(i, GetSnapshotUriResponse.MediaUri->Uri.c_str());
	}

}

void discover(struct soap *soap)
{
        struct soap* serv = soap_new1(SOAP_IO_UDP);
        if (!soap_valid_socket(soap_bind(serv, NULL, 0, 1000)))
        {
                soap_print_fault(serv, stderr);
                exit(1);
        }
        int res = soap_wsdd_Probe(serv,
                                  SOAP_WSDD_ADHOC,
                                  SOAP_WSDD_TO_TS,
                                  "soap.udp://239.255.255.250:3702",
                                  soap_wsa_rand_uuid(serv),
                                  NULL,
                                  "tds:Device",
                                  "onvif://www.onvif.org",
                                  "http://schemas.xmlsoap.org/ws/2005/04/discovery/rfc3986");
        if (res != SOAP_OK)
        {
                soap_print_fault(serv, stderr);
                exit(1);
        }
	for (int i = 0; i < 3; i++)
	        soap_wsdd_listen(serv, 1);

        soap_destroy(serv);
        soap_end(serv);
        soap_done(serv);
}

void print_usage(const char *argv0)
{
	printf("%s address username password action [action parameters]\n"
	       "actions: info discover resolutions set_resolution get_stream_urls\n", argv0);
	exit(0);
}

int main(int argc, char **argv)
{
	if (argc < 4)
		print_usage(argv[0]);

	g_hostname = argv[1];
	g_username = argv[2];
	g_password = argv[3];


	// make OpenSSL MT-safe with mutex
	CRYPTO_thread_setup();

	// create a context with strict XML validation and exclusive XML canonicalization for WS-Security enabled
	struct soap *soap = soap_new1(SOAP_XML_STRICT | SOAP_XML_CANONICAL);
	soap->fignore = skip_unknown;
	soap->connect_timeout = soap->recv_timeout = soap->send_timeout = 10; // 10 sec
	soap_register_plugin(soap, soap_wsse);

	if (soap_ssl_client_context(soap, SOAP_SSL_DEFAULT | SOAP_SSL_SKIP_HOST_CHECK, NULL, NULL, NULL, "/etc/ssl/certs", NULL))
		report_error(soap);


	if (argc == 4)
		show_info(soap);//default action
	else
	{
		if (strcmp("resolutions", argv[4]) == 0)
			show_resolutions(soap);
		else if (strcmp("get_stream_urls", argv[4]) == 0)
		{
			get_stream_urls(soap);
		}
		else if (strcmp("set_resolution", argv[4]) == 0)
		{
			if (argc < 6)
			{
				std::cerr << "Missing resolution argument!" << std::endl;
				exit(EXIT_FAILURE);
			}
			set_resolution(soap, argv[5]);
		}
		else if (strcmp("events_subscribe", argv[4]) == 0)
		{
			events_subscribe(soap);
		}
		else if (strcmp("events_unsubscribe", argv[4]) == 0)
		{
			events_unsubscribe(soap, argv[5]);
		}
		else if (strcmp("discover", argv[4]) == 0)
		{
			discover(soap);
		}
		else
		{
			std::cerr << "Unknown action: " << argv[4] << std::endl;
		}
	}

	// free all deserialized and managed data, we can still reuse the context and proxies after this
	soap_destroy(soap);
	soap_end(soap);

	// free the shared context, proxy classes must terminate as well after this
	soap_free(soap);

	// clean up OpenSSL mutex
	CRYPTO_thread_cleanup();

	return 0;
}

/******************************************************************************\
 *
 *	WS-Discovery event handlers must be defined, even when not used
 *
\******************************************************************************/

void wsdd_event_Hello(struct soap *soap, unsigned int InstanceId, const char *SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, const char *EndpointReference, const char *Types, const char *Scopes, const char *MatchBy, const char *XAddrs, unsigned int MetadataVersion)
{ }

void wsdd_event_Bye(struct soap *soap, unsigned int InstanceId, const char *SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, const char *EndpointReference, const char *Types, const char *Scopes, const char *MatchBy, const char *XAddrs, unsigned int *MetadataVersion)
{ }

soap_wsdd_mode wsdd_event_Probe(struct soap *soap, const char *MessageID, const char *ReplyTo, const char *Types, const char *Scopes, const char *MatchBy, struct wsdd__ProbeMatchesType *ProbeMatches)
{
	return SOAP_WSDD_ADHOC;
}

void wsdd_event_ProbeMatches(struct soap *soap, unsigned int InstanceId, const char *SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, struct wsdd__ProbeMatchesType *ProbeMatches)
{
	for (int i=0; i < ProbeMatches->__sizeProbeMatch; i++)
	{
		std::regex ip("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b");
		std::regex scope("onvif://www.onvif.org/([\\w/%\\-]+)");
		std::smatch m1;

		if (ProbeMatches->ProbeMatch[i].XAddrs)
		{
			std::string xaddrs(ProbeMatches->ProbeMatch[i].XAddrs);
			std::regex_search(xaddrs, m1, ip);
			if (m1.empty())
				continue;
			std::cout << m1[0] << std::endl;

			if (ProbeMatches->ProbeMatch[i].Scopes->__item)
			{
				std::string scopes(ProbeMatches->ProbeMatch[i].Scopes->__item);

				auto words_begin =
				std::sregex_iterator(scopes.begin(), scopes.end(), scope);
				auto words_end = std::sregex_iterator();

				for (std::sregex_iterator i = words_begin; i != words_end; ++i)
				{
				        std::smatch match = *i;
				        std::string match_str = match[1].str();
				        std::cout << match_str << '\n';
				}
			}
			std::cout << std::endl;
		}
	}
}

soap_wsdd_mode wsdd_event_Resolve(struct soap *soap, const char *MessageID, const char *ReplyTo, const char *EndpointReference, struct wsdd__ResolveMatchType *match)
{
	return SOAP_WSDD_ADHOC;
}

void wsdd_event_ResolveMatches(struct soap *soap, unsigned int InstanceId, const char * SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, struct wsdd__ResolveMatchType *match)
{ }

int SOAP_ENV__Fault(struct soap *soap, char *faultcode, char *faultstring, char *faultactor, struct SOAP_ENV__Detail *detail, struct SOAP_ENV__Code *SOAP_ENV__Code, struct SOAP_ENV__Reason *SOAP_ENV__Reason, char *SOAP_ENV__Node, char *SOAP_ENV__Role, struct SOAP_ENV__Detail *SOAP_ENV__Detail)
{
	// populate the fault struct from the operation arguments to print it
	soap_fault(soap);
	// SOAP 1.1
	soap->fault->faultcode = faultcode;
	soap->fault->faultstring = faultstring;
	soap->fault->faultactor = faultactor;
	soap->fault->detail = detail;
	// SOAP 1.2
	soap->fault->SOAP_ENV__Code = SOAP_ENV__Code;
	soap->fault->SOAP_ENV__Reason = SOAP_ENV__Reason;
	soap->fault->SOAP_ENV__Node = SOAP_ENV__Node;
	soap->fault->SOAP_ENV__Role = SOAP_ENV__Role;
	soap->fault->SOAP_ENV__Detail = SOAP_ENV__Detail;
	// set error
	soap->error = SOAP_FAULT;
	// handle or display the fault here with soap_stream_fault(soap, std::cerr);
	// return HTTP 202 Accepted
	return soap_send_empty_response(soap, SOAP_OK);
}

/******************************************************************************\
 *
 *	OpenSSL
 *
\******************************************************************************/

#ifdef WITH_OPENSSL

struct CRYPTO_dynlock_value
{
	MUTEX_TYPE mutex;
};

static MUTEX_TYPE *mutex_buf;

static struct CRYPTO_dynlock_value *dyn_create_function(const char *file, int line)
{
	struct CRYPTO_dynlock_value *value;
	value = (struct CRYPTO_dynlock_value*)malloc(sizeof(struct CRYPTO_dynlock_value));
	if (value)
		MUTEX_SETUP(value->mutex);
	return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(l->mutex);
	else
		MUTEX_UNLOCK(l->mutex);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	MUTEX_CLEANUP(l->mutex);
	free(l);
}

void locking_function(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(mutex_buf[n]);
	else
		MUTEX_UNLOCK(mutex_buf[n]);
}

unsigned long id_function()
{
	return (unsigned long)THREAD_ID;
}

int CRYPTO_thread_setup()
{
	int i;
	mutex_buf = (MUTEX_TYPE*)malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (!mutex_buf)
		return SOAP_EOM;
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_SETUP(mutex_buf[i]);
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	CRYPTO_set_dynlock_create_callback(dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
	return SOAP_OK;
}

void CRYPTO_thread_cleanup()
{
	int i;
	if (!mutex_buf)
		return;
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		MUTEX_CLEANUP(mutex_buf[i]);
	free(mutex_buf);
	mutex_buf = NULL;
}

#else

/* OpenSSL not used */

int CRYPTO_thread_setup()
{
	return SOAP_OK;
}

void CRYPTO_thread_cleanup()
{ }

#endif


#include "soapDeviceBindingProxy.h"
#include "soapMediaBindingProxy.h"
#include "soapPTZBindingProxy.h"
#include "soapPullPointSubscriptionBindingProxy.h"
#include "soapRemoteDiscoveryBindingProxy.h" 
#include "plugin/wsddapi.h"
#include "plugin/wsseapi.h"
#include "wsdd.nsmap"

//#define USERNAME "username"
//#define PASSWORD "password"
//#define HOSTNAME "https://12.34.56.78:9000/onvif/device_service"

#define USERNAME "admin"
#define PASSWORD "admin"
#define HOSTNAME "http://192.168.86.29/onvif/device_service"

char *g_username;
char *g_password;
char *g_hostname;

// using http instead of https is not safe unless you secure message integrity with WS-Security by uncommenting:
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

  // enable https connections with server certificate verification using cacerts.pem
  if (soap_ssl_client_context(soap, SOAP_SSL_DEFAULT | SOAP_SSL_SKIP_HOST_CHECK, NULL, NULL, NULL/*"cacerts.pem"*/, "/etc/ssl/certs", NULL))
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

void print_usage(const char *argv0)
{
	printf("%s address username password action [action parameters]\n"
		"actions: resolutions set_resolution events\n", argv0);
	exit(0);
}

int main(int argc, char **argv)
{
  char soap_endpoint[1024];
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

  // enable https connections with server certificate verification using cacerts.pem
  if (soap_ssl_client_context(soap, SOAP_SSL_DEFAULT | SOAP_SSL_SKIP_HOST_CHECK, NULL, NULL, NULL/*"cacerts.pem"*/, "/etc/ssl/certs", NULL))
    report_error(soap);

  // create the proxies to access the ONVIF service API at HOSTNAME
  DeviceBindingProxy proxyDevice(soap);
  MediaBindingProxy proxyMedia(soap);

  // get device info and print
  sprintf(soap_endpoint, "%s/onvif/device_service", g_hostname);
  proxyDevice.soap_endpoint = HOSTNAME;
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

  // for each profile get snapshot
  for (unsigned long i = 0; i < GetProfilesResponse.Profiles.size(); ++i)
  {
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
{ }

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
{ MUTEX_TYPE mutex;
};

static MUTEX_TYPE *mutex_buf;

static struct CRYPTO_dynlock_value *dyn_create_function(const char *file, int line)
{ struct CRYPTO_dynlock_value *value;
  value = (struct CRYPTO_dynlock_value*)malloc(sizeof(struct CRYPTO_dynlock_value));
  if (value)
    MUTEX_SETUP(value->mutex);
  return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{ if (mode & CRYPTO_LOCK)
    MUTEX_LOCK(l->mutex);
  else
    MUTEX_UNLOCK(l->mutex);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int line)
{ MUTEX_CLEANUP(l->mutex);
  free(l);
}

void locking_function(int mode, int n, const char *file, int line)
{ if (mode & CRYPTO_LOCK)
    MUTEX_LOCK(mutex_buf[n]);
  else
    MUTEX_UNLOCK(mutex_buf[n]);
}

unsigned long id_function()
{ return (unsigned long)THREAD_ID;
}

int CRYPTO_thread_setup()
{ int i;
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
{ int i;
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


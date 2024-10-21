
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#define MBEDTLS_DEBUG_C
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <mint/sysbind.h>
#include <gem.h>

#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"
#endif
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/version.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/timing_alt.h"

#include "transprt.h"
#include "ldg.h"

/* utils */

TPL *tpl;
DRV_LIST *drivers;

typedef struct
{
  long id;             /* Identification code */
  long value;          /* Value of the cookie */
} COOKJAR;

int xget_cookie (long cookie, void *value)
{
  static int use_ssystem = -1;
  COOKJAR *cookiejar;
  long val = -1l;
  short i = 0;
  
  if (use_ssystem < 0) { use_ssystem = (Ssystem(0xFFFF, 0l, 0) == 0); }
  
  if (use_ssystem)
  {
    if (Ssystem(0x0008, cookie, (long)&val) == 0)
    {
      if (value != NULL) { *(long *)value = val; }
      
      return TRUE;
    }
  }
  else
  {
    /* Get pointer to cookie jar */
    cookiejar = (COOKJAR *)(Setexc(0x05A0/4,(const void (*)(void))-1));
    
    if (cookiejar)
    {
      for (i = 0; cookiejar[i].id; i++)
      {
        if (cookiejar[i].id == cookie)
        {
          if (value) { *(long *)value = cookiejar[i].value; }
          
          return TRUE;
        }
      }
    }
  }
  
  return FALSE;
}

short *ldg_aes_global;
short ldg_aes_global_init = 0;

void CDECL set_aes_global(short *aes_global) { ldg_aes_global = aes_global; ldg_aes_global_init = 1; }

/* debug functions */

#if defined(MBEDTLS_DEBUG_C)
char lev[32];
char lin[32];

static void CDECL my_debug(void *dummy, int level, const char *filename, int line, const char *msg)
{
  snprintf(lev, 32, "%d", level);
  snprintf(lin, 32, "%d", line);

	(void)Cconws(lin);
	(void)Cconws(":");
	(void)Cconws(lev);
	(void)Cconws(": ");
  (void)Cconws(msg);
 
  size_t len = strlen(msg);
  if (len > 1) { if (msg[len - 1] != '\n') { (void)Cconws("\n"); } }
}
#endif

/* tcp layers functions for STiK/STinG and MiNTnet */

int used_tcp_layer = 0;
const int TCP_LAYER_DEFAULT = 0;
const int TCP_LAYER_MINTNET = 1;
const int TCP_LAYER_STIK = 2;

void CDECL force_tcp_layer(int value)
{
  if (value == TCP_LAYER_MINTNET) { used_tcp_layer = TCP_LAYER_MINTNET; }
  else if (value == TCP_LAYER_STIK) { used_tcp_layer = TCP_LAYER_STIK; }
  else { used_tcp_layer = TCP_LAYER_DEFAULT; }
}

void timing_set_system(int value);

void CDECL search_tcp_layer()
{
  used_tcp_layer = TCP_LAYER_DEFAULT;
  
  timing_set_system(1);

  if (xget_cookie(0x4D694E54L, NULL)) /* 'MiNT' */
  {
#if defined(MBEDTLS_DEBUG_C)
    (void)Cconws("MiNTnet detected\n\r");
#endif
    timing_set_system(0);
    used_tcp_layer = TCP_LAYER_MINTNET;
  }
  else if (xget_cookie(0x4D616758L, NULL) && xget_cookie(0x53434B4DL, NULL)) /* 'MagX' and 'SCKM' */
  {
#if defined(MBEDTLS_DEBUG_C)
    (void)Cconws("MagiCNet detected\n\r");
#endif
    used_tcp_layer = TCP_LAYER_MINTNET;
  }
  else if (xget_cookie(0x5354694BL, NULL)) /* 'STiK' */
  {
#if defined(MBEDTLS_DEBUG_C)
    (void)Cconws("STinG/STiK detected\n\r");
#endif
    used_tcp_layer = TCP_LAYER_STIK;
  }
}

short stick_init()
{
  unsigned long cookieval;
  
  if (xget_cookie(0x5354694BL, &cookieval) == 0)   /* 'STiK' */
  {
#if defined(MBEDTLS_DEBUG_C)
    (void)Cconws("STinG/STiK is not loaded or enabled!\n\r");
#endif
    return -1;
  }
  
  drivers = (DRV_LIST *)cookieval;
  
  if (strcmp(drivers->magic, MAGIC) != 0)
  {
#if defined(MBEDTLS_DEBUG_C)
    (void)Cconws("STinG/STiK structures corrupted!\n\r");
#endif
    return -1;
  }
  
  tpl = (TPL *)get_dftab(TRANSPORT_DRIVER);
  
  if (tpl == (TPL *)NULL)
  {
#if defined(MBEDTLS_DEBUG_C)
    (void)Cconws("Transport Driver not found!\n\r");
#endif
    return -1;
  }
  
  return 0;
}

void my_wait(unsigned long delay) { if (ldg_aes_global_init == 1) { mt_evnt_timer(delay, ldg_aes_global); } }

static const int16 STIK_RECV_MAXSIZE = 19200;
static const int16 STIK_SEND_MAXSIZE = 1920;

int my_stick_recv(void *ctx, unsigned char *buf, size_t len)
{
  int16 cn  = (int16)*((int *) ctx);
  int16 ret = E_NORMAL;
  int16 get = 0;
  int   rec = 0;
  unsigned char *ptr = buf;
  unsigned char *end = (buf + len);
  
  while ((ret > E_EOF) && (ptr < end))
  {
    ret = CNbyte_count(cn);
    
    if (ret >= E_NORMAL)
    {
      get = ret;
      
      if (get > STIK_RECV_MAXSIZE) { get = STIK_RECV_MAXSIZE; }
      
      if ((ptr + get) > end) { get = (end - ptr); }
    }
    else if (ret == E_NODATA)
    {
      my_wait(20);
    }
    
    if (get > 0)
    {
      ret = CNget_block(cn, ptr, get);
      
      if (ret > E_NORMAL) { rec += ret; ptr += ret; }
    }
  }
  
  if (ret < 0)
  {
    if (ret == E_REFUSE || ret == E_RRESET) { return MBEDTLS_ERR_NET_CONN_RESET; }
    
    return MBEDTLS_ERR_NET_RECV_FAILED;
  }

  return rec;
}

int my_stick_send(void *ctx, const unsigned char *buf, size_t len)
{
  int16 cn  = (int16)*((int *) ctx);
  int16 ret = E_NORMAL;
  int16 rem = 0;
  int   sen = 0;
  unsigned char *ptr = (unsigned char *)buf;
  
  while ((len >= STIK_SEND_MAXSIZE) && (ret > E_NODATA))
  {
    ret = TCP_send(cn, ptr, STIK_SEND_MAXSIZE);
    
    short i = 0; while ((ret == E_OBUFFULL) && (i <= 100)) { my_wait(50); ret = TCP_send(cn, ptr, STIK_SEND_MAXSIZE); ++i; }
    
    if (ret == E_NORMAL) { sen += STIK_SEND_MAXSIZE; ptr += STIK_SEND_MAXSIZE; len -= STIK_SEND_MAXSIZE; }
  }
  if ((len > 0) && (ret > E_NODATA))
  {
    rem = (int16)len;
    
    ret = TCP_send(cn, ptr, rem);
    
    short i = 0; while ((ret == E_OBUFFULL) && (i <= 100)) { my_wait(50); ret = TCP_send(cn, ptr, rem); ++i; }

    if (ret == E_NORMAL) { sen += len; }
  }
  
  if (ret < 0)
  {
    if (ret == E_REFUSE || ret == E_RRESET) { return MBEDTLS_ERR_NET_CONN_RESET; }
    
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }
  else if (ret != E_NORMAL)
  {
    return ret;
  }

  return sen;
}

int my_mintnet_recv(void *ctx, unsigned char *buf, size_t len)
{
  int fd  = *((int *) ctx);
  int ret = read(fd, buf, len);
  
  if (ret < 0)
  {
    if (errno == EAGAIN || errno == EINTR) { return MBEDTLS_ERR_SSL_WANT_READ; }
    
    if (errno == EPIPE || errno == ECONNRESET) { return MBEDTLS_ERR_NET_CONN_RESET; }
    
    return MBEDTLS_ERR_NET_RECV_FAILED;
  }
  
  return ret;
}

int my_mintnet_send(void *ctx, const unsigned char *buf, size_t len)
{
  int fd  = *((int *) ctx);
  int ret = write(fd, buf, len);
  
  if (ret < 0)
  {
    if (errno == EAGAIN || errno == EINTR) { return MBEDTLS_ERR_SSL_WANT_WRITE; }
    
    if (errno == EPIPE || errno == ECONNRESET) { return MBEDTLS_ERR_NET_CONN_RESET; }
    
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }
  
  return ret;
}

/* version */

const char* CDECL get_version() { return MBEDTLS_VERSION_STRING; }

/* certificate functions */

unsigned long CDECL get_sizeof_x509_crt_struct() { return (unsigned long)sizeof(mbedtls_x509_crt); }

void CDECL ldg_x509_crt_init(mbedtls_x509_crt *crt) { mbedtls_x509_crt_init(crt); }

int CDECL ldg_x509_crt_parse(mbedtls_x509_crt *chain, const unsigned char *buf, size_t len)
{
  /* updated X509_crt_parse() need a C-string in buf, ie buf[len - 1] == '\0', evenif it's coming from big cacert.pem file */
  return mbedtls_x509_crt_parse(chain, buf, len);
}

int CDECL ldg_x509_crt_info(char *buf, size_t size, const mbedtls_x509_crt *crt) { return mbedtls_x509_crt_info(buf, size, "", crt); }

void CDECL ldg_x509_crt_free(mbedtls_x509_crt *crt) { mbedtls_x509_crt_free(crt); }

/* private key functions (rng functions by th-otto) */

typedef struct { mbedtls_ctr_drbg_context drbg_ctx; mbedtls_entropy_context entr_ctx; } rng_context_t; // th-otto
typedef struct { mbedtls_pk_context pk; rng_context_t rng; } my_pk_context; // th-otto

unsigned long CDECL get_sizeof_pk_context_struct() { return (unsigned long)sizeof(my_pk_context); }

void CDECL ldg_pk_init(my_pk_context *pk) { mbedtls_pk_init(&pk->pk); }

void rng_init(rng_context_t *rng)
{
  mbedtls_ctr_drbg_init(&rng->drbg_ctx);
  mbedtls_entropy_init(&rng->entr_ctx);
}

static int rng_get(void *p_rng, unsigned char *output, size_t output_len)
{
  rng_context_t *rng = p_rng;
  return mbedtls_ctr_drbg_random(&rng->drbg_ctx, output, output_len);
}

int CDECL ldg_pk_parse(my_pk_context *pk, const unsigned char *key, size_t keylen)
{
  rng_init(&pk->rng);
  return mbedtls_pk_parse_key(&pk->pk, key, keylen, NULL, 0, rng_get, &pk->rng);
}

void CDECL ldg_pk_free(my_pk_context *pk) { mbedtls_pk_free(&pk->pk); }

/* entropy functions */

unsigned long CDECL get_sizeof_entropy_context_struct() { return (unsigned long)sizeof(mbedtls_entropy_context); }
unsigned long CDECL get_sizeof_ctr_drbg_context_struct() { return (unsigned long)sizeof(mbedtls_ctr_drbg_context); }

int ldg_entropy_init(mbedtls_entropy_context *entr_ctx, mbedtls_ctr_drbg_context *drbg_ctx, const char *app_name)
{
  mbedtls_ctr_drbg_init(drbg_ctx);
  mbedtls_entropy_init(entr_ctx);
  
  return mbedtls_ctr_drbg_seed(drbg_ctx, mbedtls_entropy_func, entr_ctx, (const unsigned char *) app_name, strlen(app_name));
}

void CDECL ldg_entropy_free(mbedtls_entropy_context *entr_ctx, mbedtls_ctr_drbg_context *drbg_ctx)
{
  if (drbg_ctx != NULL) { mbedtls_ctr_drbg_free(drbg_ctx); }
  if (entr_ctx != NULL) { mbedtls_entropy_free(entr_ctx); }
}

/* ssl layer functions */

typedef struct { mbedtls_ssl_config conf; mbedtls_ssl_context ssl; } my_ssl_context; // th-otto

unsigned long CDECL get_sizeof_ssl_context_struct() { return (unsigned long)sizeof(my_ssl_context); }

int CDECL ldg_ssl_init(my_ssl_context *ssl, mbedtls_ctr_drbg_context *drbg_ctx, int *server_fd, const char *servername, mbedtls_x509_crt *cacert, mbedtls_x509_crt *cert, my_pk_context *pk)
{
  int ret;
  
  mbedtls_ssl_init(&ssl->ssl);
  mbedtls_ssl_config_init(&ssl->conf);
  ret = mbedtls_ssl_config_defaults(&ssl->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) { goto exit; }
  
  mbedtls_ssl_conf_authmode(&ssl->conf, (cacert == NULL) ? MBEDTLS_SSL_VERIFY_NONE : MBEDTLS_SSL_VERIFY_OPTIONAL);
  
  mbedtls_ssl_conf_rng(&ssl->conf, mbedtls_ctr_drbg_random, drbg_ctx);
#if defined(MBEDTLS_DEBUG_C)
  mbedtls_ssl_conf_dbg(&ssl->conf, my_debug, stdout);
#endif
  if (used_tcp_layer == TCP_LAYER_STIK)
  {
    mbedtls_ssl_set_bio(&ssl->ssl, server_fd, my_stick_send, my_stick_recv, NULL);
  }
  else
  {
    mbedtls_ssl_set_bio(&ssl->ssl, server_fd, my_mintnet_send, my_mintnet_recv, NULL);
  }
  mbedtls_ssl_conf_ca_chain(&ssl->conf, cacert, NULL);
  if (cert != NULL && pk != NULL)
  {
    ret = mbedtls_ssl_conf_own_cert(&ssl->conf, cert, &pk->pk);
    if (ret != 0) { goto exit; }
  }

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
  ret = mbedtls_ssl_set_hostname(&ssl->ssl, servername);
  if (ret != 0) { goto exit; }
#endif

  return 0;
  
exit: // th-otto
  mbedtls_ssl_free(&ssl->ssl);
  mbedtls_ssl_config_free(&ssl->conf);
  return ret;
}

void CDECL ldg_ssl_set_minmax_version(my_ssl_context *ssl, int minor_min, int minor_max)
{
  if (minor_min < MBEDTLS_SSL_MINOR_VERSION_3) { minor_min = MBEDTLS_SSL_MINOR_VERSION_3; }
  if (minor_max > MBEDTLS_SSL_MINOR_VERSION_4) { minor_max = MBEDTLS_SSL_MINOR_VERSION_4; }
  if (minor_min > minor_max) { minor_min = minor_max; }
  
  mbedtls_ssl_conf_min_tls_version(&ssl->conf, (MBEDTLS_SSL_MAJOR_VERSION_3 << 8) | minor_min);
  mbedtls_ssl_conf_max_tls_version(&ssl->conf, (MBEDTLS_SSL_MAJOR_VERSION_3 << 8) | minor_max);
}

void CDECL ldg_ssl_set_ciphersuite(my_ssl_context *ssl, const int *wished_ciphersuites)
{
  mbedtls_ssl_conf_ciphersuites(&ssl->conf, wished_ciphersuites);
}

int CDECL ldg_ssl_handshake(my_ssl_context *ssl)
{
  int ret;
  struct timeval timer;

	ret = mbedtls_ssl_setup(&ssl->ssl, &ssl->conf);
	if (ret != 0) { return ret; }

  if (used_tcp_layer == TCP_LAYER_MINTNET)
  {
    timer.tv_sec = 30;
    timer.tv_usec = 0;
    
    setsockopt((int)(ssl->ssl.p_bio), SOL_SOCKET, SO_RCVTIMEO, (void*)&timer, sizeof(timer));
  }

  while (( ret = mbedtls_ssl_handshake(&ssl->ssl)) != 0) { if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) { break; } }

  if ((ret == 0) && (used_tcp_layer == TCP_LAYER_MINTNET))
  {
    timer.tv_sec = 0;
    timer.tv_usec = 0;
    
    setsockopt((int)(ssl->ssl.p_bio), SOL_SOCKET, SO_RCVTIMEO, (void*)&timer, sizeof(timer));
  }

  return ret;
}

const char* CDECL ldg_ssl_get_version(my_ssl_context *ssl) { return mbedtls_ssl_get_version(&ssl->ssl); }

const char* CDECL ldg_ssl_get_ciphersuite(my_ssl_context *ssl) { return mbedtls_ssl_get_ciphersuite(&ssl->ssl); }

int CDECL ldg_ssl_get_verify_result(my_ssl_context *ssl) { return mbedtls_ssl_get_verify_result(&ssl->ssl); }

const mbedtls_x509_crt* CDECL ldg_ssl_get_peer_cert(my_ssl_context *ssl) { return mbedtls_ssl_get_peer_cert(&ssl->ssl); }

int CDECL ldg_ssl_read(my_ssl_context *ssl, unsigned char *buf, size_t len) { return mbedtls_ssl_read(&ssl->ssl, buf, len); }

int CDECL ldg_ssl_write(my_ssl_context *ssl, const unsigned char *buf, size_t len) { return mbedtls_ssl_write(&ssl->ssl, buf, len); }

int CDECL ldg_ssl_close_notify(my_ssl_context *ssl) { return mbedtls_ssl_close_notify(&ssl->ssl); }

void CDECL ldg_ssl_free(my_ssl_context *ssl) { mbedtls_ssl_free(&ssl->ssl); mbedtls_ssl_config_free(&ssl->conf); }

/* ldg functions table */

PROC LibFunc[] =
{
  {"get_version", "const char* get_version();\n", get_version},
  
  {"set_aes_global", "void set_aes_global(short *aes_global);\n", set_aes_global},
  {"force_tcp_layer", "void force_tcp_layer(int value);\n", force_tcp_layer},

  {"get_sizeof_x509_crt_struct", "unsigned long get_sizeof_x509_crt_struct();\n", get_sizeof_x509_crt_struct},
  {"get_sizeof_pk_context_struct", "unsigned long get_sizeof_pk_context_struct();\n", get_sizeof_pk_context_struct},
  {"get_sizeof_entropy_context_struct", "unsigned long get_sizeof_entropy_context_struct();\n", get_sizeof_entropy_context_struct},
  {"get_sizeof_ctr_drbg_context_struct", "unsigned long get_sizeof_ctr_drbg_context_struct();\n", get_sizeof_ctr_drbg_context_struct},
  {"get_sizeof_ssl_context_struct", "unsigned long get_sizeof_ssl_context_struct();\n", get_sizeof_ssl_context_struct},

  {"ldg_x509_crt_init", "void ldg_x509_crt_init(x509_crt *crt);\n", ldg_x509_crt_init},
  {"ldg_x509_crt_parse", "int ldg_x509_crt_parse(x509_crt *chain, const unsigned char *buf, size_t len);\n", ldg_x509_crt_parse},
  {"ldg_x509_crt_info", "int ldg_x509_crt_info(char *buf, size_t size, const x509_crt *crt);\n", ldg_x509_crt_info},
  {"ldg_x509_crt_free", "void ldg_x509_crt_free(x509_crt *crt);\n", ldg_x509_crt_free},

  {"ldg_pk_init", "void ldg_pk_init(my_pk_context *pk);\n", ldg_pk_init},
  {"ldg_pk_parse", "int ldg_pk_parse(my_pk_context *pk, const unsigned char *key, size_t keylen);\n", ldg_pk_parse},
  {"ldg_pk_free", "void ldg_pk_free(my_pk_context *pk);\n", ldg_pk_free},

  {"ldg_entropy_init", "int ldg_entropy_init(entropy_context *entr_ctx, ctr_drbg_context *drbg_ctx, const char *app_name);\n", ldg_entropy_init},
  {"ldg_entropy_free", "void ldg_entropy_free(entropy_context *entr_ctx, ctr_drbg_context *drbg_ctx);\n", ldg_entropy_free},
  
  {"ldg_ssl_init", "int ldg_ssl_init(my_ssl_context *ssl, ctr_drbg_context *drbg_ctx, int *server_fd, const char *servername, x509_crt *cacert, x509_crt *cert, my_pk_context *pk);\n", ldg_ssl_init},
  {"ldg_ssl_set_minmax_version", "int ldg_ssl_set_minmax_version(my_ssl_context *ssl, int min, int max);\n", ldg_ssl_set_minmax_version},
  {"ldg_ssl_set_ciphersuite", "void ldg_ssl_set_ciphersuite(my_ssl_context *ssl, const int *wished_ciphersuites);\n", ldg_ssl_set_ciphersuite},
  {"ldg_ssl_handshake", "int ldg_ssl_handshake(my_ssl_context *ssl);\n", ldg_ssl_handshake},
  {"ldg_ssl_get_version", "const char* ldg_ssl_get_version(my_ssl_context *ssl);\n", ldg_ssl_get_version},
  {"ldg_ssl_get_ciphersuite", "const char* ldg_ssl_get_ciphersuite(my_ssl_context *ssl);\n", ldg_ssl_get_ciphersuite},
  {"ldg_ssl_get_verify_result", "int ldg_ssl_get_verify_result(my_ssl_context *ssl);\n", ldg_ssl_get_verify_result},
  {"ldg_ssl_get_peer_cert", "const x509_crt* ldg_ssl_get_peer_cert(my_ssl_context *ssl);\n", ldg_ssl_get_peer_cert},
  {"ldg_ssl_read", "int ldg_ssl_read( my_ssl_context *ssl, unsigned char *buf, size_t len);\n", ldg_ssl_read},
  {"ldg_ssl_write", "int ldg_ssl_write(my_ssl_context *ssl, const unsigned char *buf, size_t len);\n", ldg_ssl_write},
  {"ldg_ssl_close_notify", "int ldg_ssl_close_notify(my_ssl_context *ssl);\n", ldg_ssl_close_notify},
  {"ldg_ssl_free", "void ldg_ssl_free(my_ssl_context *ssl);\n", ldg_ssl_free}
};

LDGLIB LibLdg[] = { { 0x0001,  29, LibFunc,  "SSL/TLS functions from mbebTLS 3.6.1", 1} };

/* main function: init and memory configuration */

int main(void)
{
  ldg_init(LibLdg);

  mbedtls_platform_set_calloc_free((void *)ldg_Malloc, (void *)ldg_Free);
  
#if defined(MBEDTLS_DEBUG_C)
  (void)Cconws("mbedTLS.ldg (");
  (void)Cconws(get_version());
  (void)Cconws(") debug mode enabled\n");

  mbedtls_debug_set_threshold(3); // 0 = nothing -> 3 = full
#endif

  search_tcp_layer();
  stick_init();

  return 0;
}

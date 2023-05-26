#include "contiki-net.h"
#include "sys/log.h"
#include "os/dev/slip.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_time_t     time_t
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define READ_TIMEOUT_MS 10000   /* 5 seconds */
#define DEBUG_LEVEL 0
static struct udp_socket udp_sock;

#define RX_BUF_SIZE	4096

static uint8_t *rx_buf = NULL;
static size_t rx_buf_size = RX_BUF_SIZE;
static size_t rx_left = 0;
static uint8_t client_ip[16];
static uint16_t client_port;
static int udp_received = 0;
//static int xbee_connected = 0;

typedef struct {
	clock_time_t	start;
	uint32_t	int_ms;
	uint32_t	fin_ms;
} udp_timer_t;

PROCESS(udp_server_process, "UDP server");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/
    static void
udp_rx_callback(struct udp_socket *c,
		void *ptr,
        const uip_ipaddr_t *sender_addr,
        uint16_t sender_port,
        const uip_ipaddr_t *receiver_addr,
        uint16_t receiver_port,
        const uint8_t *data,
        uint16_t datalen)
{
	size_t new_size;

	if (rx_buf == NULL) {
		LOG_ERR("RX buffer is NULL.\n");
		return;
	}

	if ((rx_left + datalen) > RX_BUF_SIZE) {
		new_size = (rx_left + datalen + RX_BUF_SIZE - 1) & ~(RX_BUF_SIZE - 1);
		rx_buf = realloc(rx_buf, new_size);
		if (rx_buf == NULL) {
			LOG_ERR("realloc error\n");
			return;
		}

		rx_buf_size = new_size;
	}

	memcpy(rx_buf + rx_left, data, datalen);
	rx_left += datalen;

	udp_received = 1;
	client_port = sender_port;
	memcpy(client_ip, sender_addr, 16);
	process_poll(&udp_server_process);
}

static int dtls_server_send(void *ctx, const unsigned char *buf, size_t len)
{
	struct udp_socket *s = ctx;

	return udp_socket_send(s, buf, len);
}

static int dtls_server_recv(void *ctx, unsigned char *buf, size_t len)
{
	if (!rx_left)
		return MBEDTLS_ERR_SSL_WANT_READ;

	if (rx_left > len) {
		rx_left -= len;

		memcpy(buf, rx_buf, len);
		memmove(rx_buf, rx_buf + len, rx_left);
		
		return len;
	}
	else {
		len = rx_left;
		rx_left = 0;
		memcpy(buf, rx_buf, len);
		return len;
	}
}

/*
 * Set delays to watch
 */
static void timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms )
{
	udp_timer_t *ctx = (udp_timer_t *) data;

    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;
	ctx->start = clock_time();
}

/*
 * Get number of delays expired
 */
static int timing_get_delay( void *data )
{
    udp_timer_t *ctx = (udp_timer_t *) data;
    unsigned long elapsed_ms;

    if( ctx->fin_ms == 0 )
        return( -1 );

    elapsed_ms = (clock_time() - ctx->start + 1) * 1000 / CLOCK_SECOND;

    if( elapsed_ms >= ctx->fin_ms )
        return( 2 );

    if( elapsed_ms >= ctx->int_ms )
        return( 1 );

    return( 0 );
}

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
	((void) ctx);
    ((void) level);

    mbedtls_printf("%s:%04d: %s", file, line, str );
}

int mbedtls_hardware_poll( void *data,
                 unsigned char *output, size_t len, size_t *olen )
{
	static int seeded = 0;
	int i;

	if (!seeded) {
		srand(clock_time());
		seeded = 1;
	}

	for (i = 0; i < len; i++)
		output[i] = rand();

	*olen = len;

	return 0;
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
    static int ret = 0, len;
    static unsigned char buf[1024];
    static const char *pers = "dtls_server";
    static mbedtls_ssl_cookie_ctx cookie_ctx;

    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctr_drbg;
    static mbedtls_ssl_context ssl;
    static mbedtls_ssl_config conf;
    static mbedtls_x509_crt srvcert;
    static mbedtls_pk_context pkey;
    static mbedtls_timing_delay_context timer;
#if defined(MBEDTLS_SSL_CACHE_C)
    static mbedtls_ssl_cache_context cache;
#endif

    PROCESS_BEGIN();

   	rx_buf = malloc(rx_buf_size);
	if (rx_buf == NULL) {
		LOG_ERR("malloc error\n");
		goto exit;
	}
   
	mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init( &conf );
    mbedtls_ssl_cookie_init( &cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

#if defined(MBEDTLS_DEBUG_C)
    //mbedtls_debug_set_threshold( 3 );
#endif

    /*
     * 1. Load the certificates and private RSA key
     */
    printf( "\n  . Loading the server cert. and key..." );
    fflush( stdout );

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                          mbedtls_test_srv_crt_len );
    if( ret != 0 )
    {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret != 0 )
    {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key,
                         mbedtls_test_srv_key_len, NULL, 0 );
    if( ret != 0 )
    {
        printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 2. Setup the "listening" UDP socket
     */
    printf( "  . Bind on udp/*/5678 ..." );
    fflush( stdout );

	udp_socket_register(&udp_sock, NULL, udp_rx_callback);
	udp_socket_bind(&udp_sock, UDP_SERVER_PORT);

    printf( " ok\n" );

    /*
     * 3. Seed the RNG
     */
    printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 4. Setup stuff
     */
    printf( "  . Setting up the DTLS data..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache( &conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set );
#endif

    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
   if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_cookie_setup( &cookie_ctx,
                                  mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_dtls_cookies( &conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                               &cookie_ctx );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_timer_cb( &ssl, &timer, timing_set_delay,
                                            timing_get_delay );

    printf( " ok\n" );

reset:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_ssl_session_reset( &ssl );

    /*
     * 3. Wait until a client connects
     */

	PROCESS_WAIT_UNTIL(udp_received);

	udp_socket_connect(&udp_sock, (uip_ipaddr_t *)client_ip, client_port);

    /* For HelloVerifyRequest cookies */
    if( ( ret = mbedtls_ssl_set_client_transport_id( &ssl,
                    client_ip, 16 ) ) != 0 )
    {
        printf( " failed\n  ! "
                "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, &udp_sock,
                         dtls_server_send, dtls_server_recv, NULL );

    printf( " ok\n" );

    /*
     * 5. Handshake
     */
    printf( "  . Performing the DTLS handshake..." );
    fflush( stdout );

    do {
		ret = mbedtls_ssl_handshake( &ssl );
		if (ret == MBEDTLS_ERR_SSL_WANT_READ)
			PROCESS_YIELD_UNTIL(rx_left);
	}
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED )
    {
        printf( " hello verification requested\n" );
        ret = 0;
        goto reset;
    }
    else if( ret != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
        goto reset;
    }

    printf( " ok\n" );

    /*
     * 6. Read the echo Request
     */
    printf( "  < Read from client:" );
    fflush( stdout );

    len = sizeof( buf ) - 1;
    memset( buf, 0, sizeof( buf ) );

    do {
		ret = mbedtls_ssl_read( &ssl, buf, len );
		if (ret == MBEDTLS_ERR_SSL_WANT_READ)
			PROCESS_YIELD_UNTIL(rx_left);
	}
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret <= 0 )
    {
        switch( ret )
        {
            case MBEDTLS_ERR_SSL_TIMEOUT:
                printf( " timeout\n\n" );
                goto reset;

            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                printf( " connection was closed gracefully\n" );
                ret = 0;
                goto close_notify;

            default:
                printf( " mbedtls_ssl_read returned -0x%x\n\n", -ret );
                goto reset;
        }
    }

    len = ret;
    printf( " %d bytes read\n\n%s\n\n", len, buf );

    /*
     * 7. Write the 200 Response
     */
    printf( "  > Write to client:" );
    fflush( stdout );

    do ret = mbedtls_ssl_write( &ssl, buf, len );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret < 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
        goto exit;
    }

    len = ret;
    printf( " %d bytes written\n\n%s\n\n", len, buf );

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    printf( "  . Closing the connection..." );

    /* No error checking, the connection might be closed already */
    do ret = mbedtls_ssl_close_notify( &ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
    ret = 0;

    printf( " done\n" );

    goto reset;

    /*
     * Final clean-ups and exit
     */
exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        printf( "Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ssl_cookie_free( &cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free( &cache );
#endif
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    /* Shell can not handle large exit numbers -> 1 for errors */
    if( ret < 0 )
        ret = 1;

    PROCESS_END();
}


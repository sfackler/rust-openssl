#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/srp.h>
#include <openssl/txt_db.h>
#include <openssl/aes.h>

#include "ssltestlib.h"
#include "testutil.h"
#include "testutil/output.h"
#include "internal/nelem.h"
#include "../ssl/ssl_local.h"
# ifndef OPENSSL_NO_EC
#include "crypto/ec/ec_local.h"
# endif

static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;


static int babassl_cert_cb(SSL *s, void *arg)
{
    unsigned int             len;
    const unsigned char     *data;

    SSL_get0_alpn_proposed(s, &data, &len);
    if (!TEST_int_eq(len, 3))
        return 0;

    if (memcmp(data, "\x02h2", len) != 0)
        return 0;

    return 1;
}

static int babassl_cb = 0;

#ifndef OPENSSL_NO_TLS1_2
static int babassl_client_hello_callback(SSL *s, int *al, void *arg)
{
    int *exts = NULL;
    /* We only configure two ciphers, but the SCSV is added automatically. */
    const int expected_extensions[] = {
# ifndef OPENSSL_NO_EC
                                       11, 10,
# endif
                                       35, 16, 22, 23, 13};
    size_t                   len, i;
    SSL_CTX                 *ssl_ctx, *sctx2 = arg;

# ifdef SSL_client_hello_get1_extensions
    if (!SSL_client_hello_get1_extensions(s, &exts, &len))
        return SSL_CLIENT_HELLO_ERROR;
# endif

    babassl_cb++;

    if (babassl_cb == 3 && (!TEST_int_eq(len, OSSL_NELEM(expected_extensions)) ||
        !TEST_int_eq(memcmp(exts, expected_extensions, len * sizeof(*exts)), 0))) {
        printf("ClientHello callback expected extensions mismatch\n");
        printf("exts: ");
        for (i = 0; i < len; i++) {
            printf("%d ", exts[i]);
        }
        printf("\n");
        OPENSSL_free(exts);
        return SSL_CLIENT_HELLO_ERROR;
    }

    OPENSSL_free(exts);

    ssl_ctx = SSL_get_SSL_CTX(s);
# ifdef SSL_get_cert_cb
    if (SSL_get_cert_cb(s) != babassl_cert_cb)
        return SSL_CLIENT_HELLO_ERROR;
    if (!TEST_ptr_eq(SSL_get_cert_cb_arg(s), (void *)0x99))
        return SSL_CLIENT_HELLO_ERROR;
# endif

# ifdef SSL_CTX_get_cert_cb
    if (SSL_CTX_get_cert_cb(ssl_ctx) != babassl_cert_cb)
        return SSL_CLIENT_HELLO_ERROR;

    if (!TEST_ptr_eq(SSL_CTX_get_cert_cb_arg(ssl_ctx), (void *)0x99))
        return SSL_CLIENT_HELLO_ERROR;
# endif

# ifdef SSL_get0_wbio
    if (!TEST_ptr_eq(SSL_get0_wbio(s), s->wbio))
        return SSL_CLIENT_HELLO_ERROR;
# endif

    SSL_set_SSL_CTX(s, sctx2);
# ifdef SSL_set_SESSION_CTX
    SSL_set_SESSION_CTX(s, sctx2);
#endif

    SSL_set_options(s, SSL_CTX_get_options(sctx2));

    return SSL_CLIENT_HELLO_SUCCESS;
}
# endif

static int test_babassl_api(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL, *sctx2 = NULL, *sctx3 = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    size_t len;
    FILE *fp;
    const EVP_MD                       *md = NULL;
    int                                 rsig;
#ifdef SSL_CIPHER_get_mkey
    const SSL_CIPHER           *cipher;
#endif
#ifdef SSL_get_use_certificate
    X509 *x509;
#endif
#ifdef SSL_get_master_key
    int master_key_len;
    unsigned char *master_key = NULL;
#endif
#ifndef OPENSSL_NO_CRYPTO_MDEBUG_COUNT
    int count = 0;
    size_t size = 0;
#endif
#ifdef EC_POINT_get_coordinates
    const BIGNUM *x = NULL;
    const BIGNUM *y = NULL;
    const BIGNUM *z = NULL;

    EC_GROUP *group = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_POINT *P = NULL;
    BN_CTX *ctx = NULL;
#endif
#ifndef OPENSSL_NO_GLOBAL_SESSION_CACHE
    SSL_SESSION *sess;
#endif

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(),
                                       TLS1_VERSION, TLS_MAX_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(), NULL,
                                       TLS1_VERSION, TLS_MAX_VERSION,
                                       &sctx2, NULL, cert, privkey)))
        goto end;

    SSL_CTX_set_options(sctx2, SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_options(sctx2, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(sctx2, SSL_OP_NO_SSLv3);

#ifndef OPENSSL_NO_TLS1_2
    SSL_CTX_set_client_hello_cb(sctx, babassl_client_hello_callback, sctx2);
#endif
    SSL_CTX_set_cert_cb(sctx, babassl_cert_cb, (void *)0x99);
    SSL_CTX_set_cert_cb(sctx2, babassl_cert_cb, (void *)0x99);

    /* The gimpy cipher list we configure can't do TLS 1.3. */
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    if (!TEST_int_eq(SSL_CTX_set_alpn_protos(cctx, (u_char *) "\x02h2", 3), 0))
        goto end;
#endif

    SSL_CTX_set_options(cctx, SSL_OP_NO_TLSv1_2);
    SSL_CTX_set_options(cctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(cctx, SSL_OP_NO_SSLv3);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_false(create_ssl_connection(serverssl, clientssl,
                                                 SSL_ERROR_NONE)))
        goto end;

    SSL_CTX_clear_options(cctx, SSL_OP_NO_TLSv1_2);

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

    sctx3 = SSL_CTX_dup(sctx2);
#ifdef SSL_CTX_certs_clear
    SSL_CTX_certs_clear(sctx2);
#endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_false(create_ssl_connection(serverssl, clientssl,
                                                 SSL_ERROR_NONE)))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

#ifndef OPENSSL_NO_TLS1_2
    SSL_CTX_set_client_hello_cb(sctx, babassl_client_hello_callback, sctx3);
#endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_long_eq(BabaSSL_version_num(), BABASSL_VERSION_NUMBER))
        goto end;

#ifdef SSL_SESSION_get_ref
    if (!TEST_int_eq(SSL_SESSION_get_ref(SSL_get_session(serverssl)), 1))
        goto end;
#endif

#ifdef SSL_get_use_certificate
    x509 = SSL_get_use_certificate(serverssl);
    if (!TEST_ptr_eq(x509, SSL_get_certificate(serverssl)))
        goto end;
#endif

    fflush(stdout);
    setvbuf(stdout, NULL, _IONBF, 0);
    fp = freopen("BABASSL_debug.log", "w", stdout);
    BABASSL_debug(serverssl, (unsigned char *)"BABASSL_debug",
                  sizeof("BABASSL_debug") - 1);
    fseek(fp, 0, SEEK_END);

    len = 30;
#ifdef _WIN32
    /* \n -> \r\n on Windows */
    len += 2;
#endif
    if(!TEST_int_eq(ftell(fp), len))
        goto end;
    fclose(fp);
#ifdef OPENSSL_SYS_MSDOS
# define DEV_TTY "con"
#else
# define DEV_TTY "/dev/tty"
#endif
    fp = freopen(DEV_TTY, "w", stdout);
    remove("BABASSL_debug.log");

#ifdef SSL_get_master_key
    if (SSL_get_master_key(serverssl, &master_key, &master_key_len), 0)
        goto end;

    if (!TEST_int_eq(master_key_len, 48))
        goto end;

    if (!TEST_ptr_ne(master_key, NULL))
        goto end;
#endif

#ifdef SSL_CIPHER_get_mkey
    cipher = SSL_get_current_cipher(serverssl);
    if (cipher == NULL)
        goto end;

    if (!TEST_long_eq(SSL_CIPHER_get_mkey(cipher), cipher->algorithm_mkey))
        goto end;

    if (!TEST_long_eq(SSL_CIPHER_get_mac(cipher), cipher->algorithm_mac))
        goto end;

    if (!TEST_long_eq(SSL_CIPHER_get_enc(cipher), cipher->algorithm_enc))
        goto end;

    if (!TEST_long_eq(SSL_CIPHER_get_auth(cipher), cipher->algorithm_auth))
        goto end;
#endif

#ifdef SSL_get_sig_hash
    if (!TEST_int_eq(SSL_get_sig_hash(serverssl), serverssl->sig_hash))
        goto end;
#endif

    tls1_lookup_get_sig_and_md(0x0804, &rsig, &md);
    if (!TEST_int_eq(rsig, EVP_PKEY_RSA_PSS))
        goto end;

    if (!TEST_ptr_ne(md, NULL))
        goto end;

#ifndef OPENSSL_NO_CRYPTO_MDEBUG_COUNT
    CRYPTO_get_mem_counts(&count, &size);
    if (!TEST_int_eq(count, 0))
        goto end;
    if (!TEST_size_t_gt(size, 0))
        goto end;
#endif

#ifdef EC_POINT_get_coordinates

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_true(BN_hex2bn(&p, "17"))
        || !TEST_true(BN_hex2bn(&a, "1"))
        || !TEST_true(BN_hex2bn(&b, "1"))
        /*
         * applications should use EC_GROUP_new_curve_GFp so
         * that the library gets to choose the EC_METHOD
         */
        || !TEST_ptr(group = EC_GROUP_new(EC_GFp_mont_method()))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_true(EC_GROUP_set_curve(group, p, a, b, ctx)))
        goto end;

    EC_POINT_get_coordinates(P, &x, &y, &z);

    if (!TEST_ptr_eq(x, P->X))
        goto end;

    if (!TEST_ptr_eq(y, P->Y))
        goto end;

    if (!TEST_ptr_eq(z, P->Z))
        goto end;
#endif

#ifndef OPENSSL_NO_SESSION_REUSED_TYPE
    if (!TEST_int_eq(SSL_get_session_reused_type(serverssl),
                     serverssl->session_reused_type))
        goto end;
#endif

#ifndef OPENSSL_NO_SESSION_LOOKUP
    if (!TEST_ptr(SSL_magic_pending_session_ptr()))
        goto end;
#endif

#ifndef OPENSSL_NO_GLOBAL_SESSION_CACHE
    sess = SSL_get_session(clientssl);
    if (!TEST_ptr(sess))
        goto end;

    SSL_set_global_session_result(serverssl, sess);

    if (!TEST_ptr_eq(serverssl->global_session_result, sess))
        goto end;
#endif

    testresult = 1;

end:
#ifdef EC_POINT_get_coordinates
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_POINT_free(P);
    EC_GROUP_free(group);
#endif
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx2);
    SSL_CTX_free(sctx3);

    return testresult;
}

#ifndef OPENSSL_NO_SKIP_SCSV
static int skip_scsv_cert_cb_called = 0;

static int babassl_skip_scsv_cert_cb(SSL *s, void *arg)
{
    skip_scsv_cert_cb_called = 1;
    return 1;
}

# ifndef OPENSSL_NO_TLS1_2
static int babassl_skip_scsv_client_hello_callback(SSL *s, int *al, void *arg)
{
    SSL_set_skip_scsv(s, 1);
    return 1;
}
# endif

static int test_babassl_skip_scsv(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(),
                                       TLS1_VERSION, TLS_MAX_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

# ifndef OPENSSL_NO_TLS1_2
    SSL_CTX_set_client_hello_cb(sctx, babassl_skip_scsv_client_hello_callback,
                                sctx);
# endif
    SSL_CTX_set_cert_cb(sctx, babassl_skip_scsv_cert_cb, (void *)0x99);

    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);

    SSL_CTX_set_options(cctx, SSL_OP_NO_TLSv1_2);

    SSL_CTX_set_mode(cctx, SSL_MODE_SEND_FALLBACK_SCSV);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_false(create_ssl_connection(serverssl, clientssl,
                                                 SSL_ERROR_NONE))
            || !TEST_int_eq(serverssl->version, 0x302)
            || !TEST_int_eq(skip_scsv_cert_cb_called, 1)
            || !TEST_int_ne(serverssl->version, sctx->method->version))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif

#ifndef OPENSSL_NO_VERIFY_SNI
static int test_babassl_verify_cert_with_sni(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(),
                                       TLS1_VERSION, TLS_MAX_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);

    SSL_CTX_set_verify_cert_with_sni(sctx, 1);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto end;

    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "badservername.example"))
        || !TEST_false(create_ssl_connection(serverssl, clientssl,
                                             SSL_ERROR_NONE)))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto end;

    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example"))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                            SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_CTX_get_verify_cert_with_sni(sctx),
                     sctx->verify_mode & SSL_VERIFY_FAIL_IF_SNI_NOT_MATCH_CERT))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif

#ifndef OPENSSL_NO_DYNAMIC_CIPHERS

# ifndef OPENSSL_NO_TLS1_2
static STACK_OF(SSL_CIPHER)       *cipher_list = NULL;
static STACK_OF(SSL_CIPHER)       *cipher_list_by_id = NULL;
static int dynamic_ciphers_cb_count = 0;

static int babassl_dynamic_ciphers_client_hello_callback(SSL *s, int *al, void *arg)
{
    if (dynamic_ciphers_cb_count == 0) {
        if (!TEST_true(SSL_set_cipher_list(s, "AES128-SHA")))
            return 0;

        cipher_list = SSL_dup_ciphers(s);
        cipher_list_by_id = SSL_dup_ciphers_by_id(s);
    }

    if (cipher_list) {
        SSL_set_ciphers(s, cipher_list);
        SSL_set_ciphers_by_id(s, cipher_list_by_id);
    }

    dynamic_ciphers_cb_count++;

    return 1;
}
# endif

static int test_babassl_dynamic_ciphers(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL, *sctx2 = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(),
                                       TLS1_VERSION, TLS_MAX_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

# ifndef OPENSSL_NO_TLS1_2
    SSL_CTX_set_client_hello_cb(sctx, babassl_dynamic_ciphers_client_hello_callback,
                                sctx);
# endif
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);

    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES256-GCM-SHA384")))
        goto end;

    SSL_CTX_set_options(sctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(serverssl)),
                     0x002f))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;


    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(serverssl)),
                     0x002f))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

    if (cipher_list)
        sk_SSL_CIPHER_free(cipher_list);

    if (cipher_list_by_id)
        sk_SSL_CIPHER_free(cipher_list_by_id);

    cipher_list = SSL_CTX_get_ciphers(sctx);
    cipher_list_by_id = SSL_CTX_get_ciphers_by_id(sctx);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(serverssl)),
                     0x009d))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

    if (!TEST_true(create_ssl_ctx_pair(TLS_server_method(), NULL,
                                       TLS1_VERSION, TLS_MAX_VERSION,
                                       &sctx2, NULL, cert, privkey)))
        goto end;

    if (!TEST_true(SSL_CTX_set_cipher_list(sctx2, "AES128-SHA256")))
        goto end;

    cipher_list = SSL_CTX_get_ciphers(sctx2);
    cipher_list_by_id = SSL_CTX_get_ciphers_by_id(sctx2);

    SSL_CTX_set_ciphers(sctx, cipher_list);
    SSL_CTX_set_ciphers_by_id(sctx, cipher_list_by_id);

    cipher_list = NULL;
    cipher_list_by_id = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(serverssl)),
                     0x003C))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx2);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif

#if defined(SSL_check_tlsext_status) && !defined(OPENSSL_NO_OCSP)

static int ocsp_server_called = 0;

static int ocsp_server_cb(SSL *s, void *arg)
{
    if (!TEST_int_eq(SSL_check_tlsext_status(s), TLSEXT_STATUSTYPE_ocsp))
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    ocsp_server_called = 1;

    return SSL_TLSEXT_ERR_OK;
}

static int test_babassl_tlsext_status(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;

    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(),
                             TLS1_VERSION, TLS_MAX_VERSION,
                             &sctx, &cctx, cert, privkey))
        return 0;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE))
            || !TEST_int_ne(SSL_check_tlsext_status(serverssl),
                            TLSEXT_STATUSTYPE_ocsp)
            || !TEST_false(ocsp_server_called))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = NULL;
    clientssl = NULL;

    if (!SSL_CTX_set_tlsext_status_type(cctx, TLSEXT_STATUSTYPE_ocsp))
        goto end;

    SSL_CTX_set_tlsext_status_cb(sctx, ocsp_server_cb);
    SSL_CTX_set_tlsext_status_arg(sctx, NULL);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE))
            || !TEST_int_eq(SSL_check_tlsext_status(serverssl),
                            TLSEXT_STATUSTYPE_ocsp)
            || !TEST_true(ocsp_server_called))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif

#ifndef OPENSSL_NO_STATUS
static int status_cb_called = 0;

static int status_callback(unsigned char *p, unsigned int length,
    SSL_status *param)
{
    status_cb_called = 1;
    return 1;
}

static int test_babassl_status_api(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0, alert_level = 0, alert_desc = 0;

    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(),
                             TLS1_VERSION, TLS_MAX_VERSION,
                             &sctx, &cctx, cert, privkey))
        return 0;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL)))
        goto end;

    SSL_set_status_callback(serverssl, status_callback, 1, NULL);

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(status_cb_called, 1)
        || !TEST_true(SSL_get_status_callback(serverssl) == status_callback))
        goto end;

    if (!TEST_true(SSL_get_desc_and_level(serverssl, &alert_level, &alert_desc))
        || !TEST_int_eq(serverssl->s3->alert_level, alert_level))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif

int setup_tests(void)
{
    if (!TEST_ptr(certsdir = test_get_argument(0)))
        return 0;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        return 0;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL) {
        OPENSSL_free(cert);
        return 0;
    }

    ADD_TEST(test_babassl_api);
#ifndef OPENSSL_NO_SKIP_SCSV
    ADD_TEST(test_babassl_skip_scsv);
#endif
#ifndef OPENSSL_NO_VERIFY_SNI
    ADD_TEST(test_babassl_verify_cert_with_sni);
#endif
#ifndef OPENSSL_NO_DYNAMIC_CIPHERS
    ADD_TEST(test_babassl_dynamic_ciphers);
#endif
#if defined(SSL_check_tlsext_status) && !defined(OPENSSL_NO_OCSP)
    ADD_TEST(test_babassl_tlsext_status);
#endif
#ifndef OPENSSL_NO_STATUS
    ADD_TEST(test_babassl_status_api);
#endif
    return 1;
}

void cleanup_tests(void)
{
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    bio_s_mempacket_test_free();
    bio_s_always_retry_free();
}

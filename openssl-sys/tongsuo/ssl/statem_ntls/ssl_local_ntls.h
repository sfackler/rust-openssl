/*
 * Copyright 2019 The BabaSSL Project Authors. All Rights Reserved.
 */

#ifndef OSSL_SSL_LOCAL_NTLS_H
# define OSSL_SSL_LOCAL_NTLS_H

# include "../ssl_local.h"
# include "statem.h"

# define SSL_CLIENT_USE_SIGALGS_NTLS(s)        \
     (SSL_CLIENT_USE_TLS1_2_CIPHERS(s) || (s->client_version == NTLS_VERSION))

/*
 *optimize later
 *This is the default ID for NTLS context
 */
# define SM2_DEFAULT_ID "1234567812345678"
# define SM2_DEFAULT_ID_LEN (sizeof(SM2_DEFAULT_ID) - 1)

__owur int ssl_x509err2alert_ntls(int type);
__owur int ssl3_do_write_ntls(SSL *s, int type);
__owur unsigned long ssl3_output_cert_chain_ntls(SSL *s, WPACKET *pkt,
                                                 CERT_PKEY *a_cpk,
                                                 CERT_PKEY *k_cpk);
__owur int tls_close_construct_packet_ntls(SSL *s, WPACKET *pkt, int htype);
__owur int tls_setup_handshake_ntls(SSL *s);

__owur int ssl_allow_compression_ntls(SSL *s);

__owur int ssl_version_supported_ntls(const SSL *s, int version,
                                 const SSL_METHOD **meth);

__owur int ssl_set_client_hello_version_ntls(SSL *s);
__owur int ssl_check_version_downgrade_ntls(SSL *s);
__owur int ssl_set_version_bound_ntls(int method_version, int version, int *bound);
__owur int ssl_choose_server_version_ntls(SSL *s, CLIENTHELLO_MSG *hello,
                                     DOWNGRADE *dgrd);
__owur int ssl_choose_client_version_ntls(SSL *s, int version,
                                     RAW_EXTENSION *extensions);
__owur int ssl_get_min_max_version_ntls(const SSL *s, int *min_version,
                                   int *max_version, int *real_max);

__owur int ntls_alert_code(int code);
__owur int send_certificate_request_ntls(SSL *s);

/* statem/extensions_cust.c */

custom_ext_method *custom_ext_find_ntls(const custom_ext_methods *exts,
                                   ENDPOINT role, unsigned int ext_type,
                                   size_t *idx);

void custom_ext_init_ntls(custom_ext_methods *meths);

__owur int custom_ext_parse_ntls(SSL *s, unsigned int context, unsigned int ext_type,
                            const unsigned char *ext_data, size_t ext_size,
                            X509 *x, size_t chainidx);
__owur int custom_ext_add_ntls(SSL *s, int context, WPACKET *pkt, X509 *x,
                          size_t chainidx, int maxversion);

__owur int custom_exts_copy_ntls(custom_ext_methods *dst,
                            const custom_ext_methods *src);
__owur int custom_exts_copy_flags_ntls(custom_ext_methods *dst,
                                  const custom_ext_methods *src);
void custom_exts_free_ntls(custom_ext_methods *exts);

void ssl_comp_free_compression_methods_int(void);

/* ssl_mcnf.c */
void ssl_ctx_system_config(SSL_CTX *ctx);

#endif

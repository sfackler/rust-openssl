/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ssl_local.h"
#include "internal/cryptlib.h"
#include "internal/refcount.h"

#ifdef OPENSSL_NO_QUIC
NON_EMPTY_TRANSLATION_UNIT
#else

int SSL_set_quic_transport_params(SSL *ssl, const uint8_t *params,
                                  size_t params_len)
{
    uint8_t *tmp;

    if (params == NULL || params_len == 0) {
        tmp = NULL;
        params_len = 0;
    } else {
        tmp = OPENSSL_memdup(params, params_len);
        if (tmp == NULL)
            return 0;
    }

    OPENSSL_free(ssl->ext.quic_transport_params);
    ssl->ext.quic_transport_params = tmp;
    ssl->ext.quic_transport_params_len = params_len;
    return 1;
}

void SSL_get_peer_quic_transport_params(const SSL *ssl,
                                        const uint8_t **out_params,
                                        size_t *out_params_len)
{
    if (ssl->ext.peer_quic_transport_params_len) {
        *out_params = ssl->ext.peer_quic_transport_params;
        *out_params_len = ssl->ext.peer_quic_transport_params_len;
    } else {
        *out_params = ssl->ext.peer_quic_transport_params_draft;
        *out_params_len = ssl->ext.peer_quic_transport_params_draft_len;
    }
}

/* Returns the negotiated version, or -1 on error */
int SSL_get_peer_quic_transport_version(const SSL *ssl)
{
    if (ssl->ext.peer_quic_transport_params_len != 0
            && ssl->ext.peer_quic_transport_params_draft_len != 0)
        return -1;
    if (ssl->ext.peer_quic_transport_params_len != 0)
        return TLSEXT_TYPE_quic_transport_parameters;
    if (ssl->ext.peer_quic_transport_params_draft_len != 0)
        return TLSEXT_TYPE_quic_transport_parameters_draft;

    return -1;
}

void SSL_set_quic_use_legacy_codepoint(SSL *ssl, int use_legacy)
{
    if (use_legacy)
        ssl->quic_transport_version = TLSEXT_TYPE_quic_transport_parameters_draft;
    else
        ssl->quic_transport_version = TLSEXT_TYPE_quic_transport_parameters;
}

void SSL_set_quic_transport_version(SSL *ssl, int version)
{
    ssl->quic_transport_version = version;
}

int SSL_get_quic_transport_version(const SSL *ssl)
{
    return ssl->quic_transport_version;
}

size_t SSL_quic_max_handshake_flight_len(const SSL *ssl, OSSL_ENCRYPTION_LEVEL level)
{
    /*
     * Limits flights to 16K by default when there are no large
     * (certificate-carrying) messages.
     */
    static const size_t DEFAULT_FLIGHT_LIMIT = 16384;

    switch (level) {
    case ssl_encryption_initial:
        return DEFAULT_FLIGHT_LIMIT;
    case ssl_encryption_early_data:
        /* QUIC does not send EndOfEarlyData. */
        return 0;
    case ssl_encryption_handshake:
        if (ssl->server) {
            /*
             * Servers may receive Certificate message if configured to request
             * client certificates.
             */
            if ((ssl->verify_mode & SSL_VERIFY_PEER)
                    && ssl->max_cert_list > DEFAULT_FLIGHT_LIMIT)
                return ssl->max_cert_list;
        } else {
            /*
             * Clients may receive both Certificate message and a CertificateRequest
             * message.
             */
            if (2*ssl->max_cert_list > DEFAULT_FLIGHT_LIMIT)
                return 2 * ssl->max_cert_list;
        }
        return DEFAULT_FLIGHT_LIMIT;
    case ssl_encryption_application:
        return DEFAULT_FLIGHT_LIMIT;
    }

    return 0;
}

OSSL_ENCRYPTION_LEVEL SSL_quic_read_level(const SSL *ssl)
{
    return ssl->quic_read_level;
}

OSSL_ENCRYPTION_LEVEL SSL_quic_write_level(const SSL *ssl)
{
    return ssl->quic_write_level;
}

int SSL_provide_quic_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                          const uint8_t *data, size_t len)
{
    size_t l, offset;

    if (!SSL_IS_QUIC(ssl)) {
        SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    /* Level can be different than the current read, but not less */
    if (level < ssl->quic_read_level
            || (ssl->quic_input_data_tail != NULL && level < ssl->quic_input_data_tail->level)
            || level < ssl->quic_latest_level_received) {
        SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, SSL_R_WRONG_ENCRYPTION_LEVEL_RECEIVED);
        return 0;
    }

    if (len == 0)
        return 1;

    if (ssl->quic_buf == NULL) {
        BUF_MEM *buf;
        if ((buf = BUF_MEM_new()) == NULL) {
            SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
            SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, ERR_R_INTERNAL_ERROR);
            BUF_MEM_free(buf);
            return 0;
        }
        ssl->quic_buf = buf;
        /* We preallocated storage, but there's still no *data*. */
        ssl->quic_buf->length = 0;
        buf = NULL;
    }

    /* A TLS message must not cross an encryption level boundary */
    if (ssl->quic_buf->length != ssl->quic_next_record_start
            && level != ssl->quic_latest_level_received) {
        SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA,
               SSL_R_WRONG_ENCRYPTION_LEVEL_RECEIVED);
        return 0;
    }
    ssl->quic_latest_level_received = level;

    offset = ssl->quic_buf->length;
    if (!BUF_MEM_grow(ssl->quic_buf, offset + len)) {
        SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    memcpy(ssl->quic_buf->data + offset, data, len);

    /* Split on handshake message boundaries */
    while (ssl->quic_buf->length > ssl->quic_next_record_start
                                   + SSL3_HM_HEADER_LENGTH) {
        QUIC_DATA *qd;
        const uint8_t *p;

        /* TLS Handshake message header has 1-byte type and 3-byte length */
        p = (const uint8_t *)ssl->quic_buf->data
            + ssl->quic_next_record_start + 1;
        n2l3(p, l);
        l += SSL3_HM_HEADER_LENGTH;
        /* Don't allocate a QUIC_DATA if we don't have a full record */
        if (l > ssl->quic_buf->length - ssl->quic_next_record_start)
            break;

        qd = OPENSSL_zalloc(sizeof(*qd));
        if (qd == NULL) {
            SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        qd->next = NULL;
        qd->length = l;
        qd->start = ssl->quic_next_record_start;
        qd->level = level;

        if (ssl->quic_input_data_tail != NULL)
            ssl->quic_input_data_tail->next = qd;
        else
            ssl->quic_input_data_head = qd;
        ssl->quic_input_data_tail = qd;
        ssl->quic_next_record_start += l;
    }

    return 1;
}

int SSL_CTX_set_quic_method(SSL_CTX *ctx, const SSL_QUIC_METHOD *quic_method)
{
    if (ctx->method->version != TLS_ANY_VERSION)
        return 0;
    ctx->quic_method = quic_method;
    ctx->options &= ~SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    return 1;
}

int SSL_set_quic_method(SSL *ssl, const SSL_QUIC_METHOD *quic_method)
{
    if (ssl->method->version != TLS_ANY_VERSION)
        return 0;
    ssl->quic_method = quic_method;
    ssl->options &= ~SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    return 1;
}

int quic_set_encryption_secrets(SSL *s, OSSL_ENCRYPTION_LEVEL level)
{
    uint8_t *c2s_secret = NULL;
    uint8_t *s2c_secret = NULL;
    uint8_t *read_secret = NULL;
    uint8_t *write_secret = NULL;
    size_t len;
    const EVP_MD *md;
    const SSL_CIPHER *c = NULL;

    if (!SSL_IS_QUIC(s))
        return 1;

    /* secrets from the POV of the client */
    switch (level) {
    case ssl_encryption_early_data:
        c2s_secret = s->client_early_traffic_secret;
        break;
    case ssl_encryption_handshake:
        c2s_secret = s->client_hand_traffic_secret;
        s2c_secret = s->server_hand_traffic_secret;
        break;
    case ssl_encryption_application:
        c2s_secret = s->client_app_traffic_secret;
        s2c_secret = s->server_app_traffic_secret;
        break;
    default:
        return 1;
    }

    c = SSL_SESSION_get0_cipher(s->session);

    if (s->early_data_state == SSL_EARLY_DATA_CONNECTING
        && s->max_early_data > 0 && s->session->ext.max_early_data == 0) {
        /*
         * If we are attempting to send early data, and we've decided to
         * actually do it but max_early_data in s->session is 0 then we
         * must be using an external PSK.
         */
        if (!ossl_assert(s->psksession != NULL
                         && s->max_early_data
                            == s->psksession->ext.max_early_data)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_QUIC_SET_ENCRYPTION_SECRETS, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        c = SSL_SESSION_get0_cipher(s->psksession);
    }

    if (c == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_QUIC_SET_ENCRYPTION_SECRETS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    md = ssl_handshake_md(s);
    if (md == NULL) {
        md = SSL_CIPHER_get_handshake_digest(c);
    }

    if ((len = EVP_MD_size(md)) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_QUIC_SET_ENCRYPTION_SECRETS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    read_secret = s->server ? c2s_secret : s2c_secret;
    write_secret = s->server ? s2c_secret : c2s_secret;

    if (read_secret &&
        !s->quic_method->set_read_secret(s, level, c, read_secret, len)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_QUIC_SET_ENCRYPTION_SECRETS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (write_secret &&
        !s->quic_method->set_write_secret(s, level, c, write_secret, len)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_QUIC_SET_ENCRYPTION_SECRETS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int SSL_process_quic_post_handshake(SSL *ssl)
{
    int ret;

    if (SSL_in_init(ssl) || !SSL_IS_QUIC(ssl)) {
        SSLerr(SSL_F_SSL_PROCESS_QUIC_POST_HANDSHAKE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    /* if there is no data, return success as BoringSSL */
    while (ssl->quic_input_data_head != NULL) {
        /*
         * This is always safe (we are sure to be at a record boundary) because
         * SSL_read()/SSL_write() are never used for QUIC connections -- the
         * application data is handled at the QUIC layer instead.
         */
        ossl_statem_set_in_init(ssl, 1);
        ret = ssl->handshake_func(ssl);
        ossl_statem_set_in_init(ssl, 0);

        if (ret <= 0)
            return 0;
    }
    return 1;
}

int SSL_is_quic(SSL *ssl)
{
    return SSL_IS_QUIC(ssl);
}

void SSL_set_quic_early_data_enabled(SSL *ssl, int enabled)
{
    if (!SSL_is_quic(ssl) || !SSL_in_before(ssl))
        return;

    if (!enabled) {
        ssl->early_data_state = SSL_EARLY_DATA_NONE;
        return;
    }

    if (ssl->server) {
        ssl->early_data_state = SSL_EARLY_DATA_ACCEPTING;
        return;
    }

    if ((ssl->session == NULL || ssl->session->ext.max_early_data == 0)
            && ssl->psk_use_session_cb == NULL)
        return;

    ssl->early_data_state = SSL_EARLY_DATA_CONNECTING;
}

int SSL_set_quic_early_data_context(SSL *ssl, const uint8_t *context,
                                    size_t context_len)

{
    uint8_t *tmp;

    if (context == NULL || context_len == 0) {
        tmp = NULL;
        context_len = 0;
    } else {
        tmp = OPENSSL_memdup(context, context_len);
        if (tmp == NULL)
            return 0;
    }

    OPENSSL_free(ssl->quic_early_data_context);
    ssl->quic_early_data_context = tmp;
    ssl->quic_early_data_context_len = context_len;
    return 1;
}

#endif

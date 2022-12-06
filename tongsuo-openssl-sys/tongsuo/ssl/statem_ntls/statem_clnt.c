/*
 * Copyright 2019 The BabaSSL Project Authors. All Rights Reserved.
 */

#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "ssl_local_ntls.h"
#include "statem_local_ntls.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <internal/cryptlib.h>

#ifndef OPENSSL_NO_NTLS
static MSG_PROCESS_RETURN tls_process_as_hello_retry_request(SSL *s, PACKET *pkt);
static MSG_PROCESS_RETURN tls_process_encrypted_extensions(SSL *s, PACKET *pkt);

static ossl_inline int cert_req_allowed(SSL *s);
static int key_exchange_expected(SSL *s);
static int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk,
                                    WPACKET *pkt);

/*
 * Is a CertificateRequest message allowed at the moment or not?
 *
 *  Return values are:
 *  1: Yes
 *  0: No
 */
static ossl_inline int cert_req_allowed(SSL *s)
{
    /* TLS does not like anon-DH with client cert */
    if ((s->version > SSL3_VERSION
         && (s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL))
        || (s->s3->tmp.new_cipher->algorithm_auth & (SSL_aSRP | SSL_aPSK)))
        return 0;

    return 1;
}

/*
 * Should we expect the ServerKeyExchange message or not?
 *
 *  Return values are:
 *  1: Yes
 *  0: No
 */
static int key_exchange_expected(SSL *s)
{
    return 1;
}


/*
 * ossl_statem_client_read_transition_ntls() encapsulates the logic for the allowed
 * handshake state transitions when the client is reading messages from the
 * server. The message type that the server has sent is provided in |mt|. The
 * current state is in |s->statem.hand_state|.
 *
 * Return values are 1 for success (transition allowed) and  0 on error
 * (transition not allowed)
 */
int ossl_statem_client_read_transition_ntls(SSL *s, int mt)
{
    OSSL_STATEM *st = &s->statem;
    int ske_expected;

    /*
     * Note that after writing the first ClientHello we don't know what version
     * we are going to negotiate yet, so we don't take this branch until later.
     */

    switch (st->hand_state) {
    default:
        break;

    case TLS_ST_CW_CLNT_HELLO:
        if (mt == SSL3_MT_SERVER_HELLO) {
            st->hand_state = TLS_ST_CR_SRVR_HELLO;
            return 1;
        }

        break;

    case TLS_ST_EARLY_DATA:
        /*
         * We've not actually selected TLSv1.3 yet, but we have sent early
         * data. The only thing allowed now is a ServerHello or a
         * HelloRetryRequest.
         */
        if (mt == SSL3_MT_SERVER_HELLO) {
            st->hand_state = TLS_ST_CR_SRVR_HELLO;
            return 1;
        }
        break;

    case TLS_ST_CR_SRVR_HELLO:
        if (s->hit) {
            if (s->ext.ticket_expected) {
                if (mt == SSL3_MT_NEWSESSION_TICKET) {
                    st->hand_state = TLS_ST_CR_SESSION_TICKET;
                    return 1;
                }
            } else if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
                st->hand_state = TLS_ST_CR_CHANGE;
                return 1;
            }
        } else {
            if (s->version >= TLS1_VERSION
                       && s->ext.session_secret_cb != NULL
                       && s->session->ext.tick != NULL
                       && mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
                /*
                 * Normally, we can tell if the server is resuming the session
                 * from the session ID. EAP-FAST (RFC 4851), however, relies on
                 * the next server message after the ServerHello to determine if
                 * the server is resuming.
                 */
                s->hit = 1;
                st->hand_state = TLS_ST_CR_CHANGE;
                return 1;
            } else if (!(s->s3->tmp.new_cipher->algorithm_auth
                         & (SSL_aNULL | SSL_aSRP | SSL_aPSK))) {
                if (mt == SSL3_MT_CERTIFICATE) {
                    st->hand_state = TLS_ST_CR_CERT;
                    return 1;
                }
            } else {
                ske_expected = key_exchange_expected(s);
                /* SKE is optional for some PSK ciphersuites */
                if (ske_expected
                    || ((s->s3->tmp.new_cipher->algorithm_mkey & SSL_PSK)
                        && mt == SSL3_MT_SERVER_KEY_EXCHANGE)) {
                    if (mt == SSL3_MT_SERVER_KEY_EXCHANGE) {
                        st->hand_state = TLS_ST_CR_KEY_EXCH;
                        return 1;
                    }
                } else if (mt == SSL3_MT_CERTIFICATE_REQUEST
                           && cert_req_allowed(s)) {
                    st->hand_state = TLS_ST_CR_CERT_REQ;
                    return 1;
                } else if (mt == SSL3_MT_SERVER_DONE) {
                    st->hand_state = TLS_ST_CR_SRVR_DONE;
                    return 1;
                }
            }
        }
        break;

    case TLS_ST_CR_CERT:
        /*
         * The CertificateStatus message is optional even if
         * |ext.status_expected| is set
         */
        if (s->ext.status_expected && mt == SSL3_MT_CERTIFICATE_STATUS) {
            st->hand_state = TLS_ST_CR_CERT_STATUS;
            return 1;
        }
        /* Fall through */

    case TLS_ST_CR_CERT_STATUS:
        ske_expected = key_exchange_expected(s);
        /* SKE is optional for some PSK ciphersuites */
        if (ske_expected || ((s->s3->tmp.new_cipher->algorithm_mkey & SSL_PSK)
                             && mt == SSL3_MT_SERVER_KEY_EXCHANGE)) {
            if (mt == SSL3_MT_SERVER_KEY_EXCHANGE) {
                st->hand_state = TLS_ST_CR_KEY_EXCH;
                return 1;
            }
            goto err;
        }
        /* Fall through */

    case TLS_ST_CR_KEY_EXCH:
        if (mt == SSL3_MT_CERTIFICATE_REQUEST) {
            if (cert_req_allowed(s)) {
                st->hand_state = TLS_ST_CR_CERT_REQ;
                return 1;
            }
            goto err;
        }
        /* Fall through */

    case TLS_ST_CR_CERT_REQ:
        if (mt == SSL3_MT_SERVER_DONE) {
            st->hand_state = TLS_ST_CR_SRVR_DONE;
            return 1;
        }
        break;

    case TLS_ST_CW_FINISHED:
        if (s->ext.ticket_expected) {
            if (mt == SSL3_MT_NEWSESSION_TICKET) {
                st->hand_state = TLS_ST_CR_SESSION_TICKET;
                return 1;
            }
        } else if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_CR_CHANGE;
            return 1;
        }
        break;

    case TLS_ST_CR_SESSION_TICKET:
        if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_CR_CHANGE;
            return 1;
        }
        break;

    case TLS_ST_CR_CHANGE:
        if (mt == SSL3_MT_FINISHED) {
            st->hand_state = TLS_ST_CR_FINISHED;
            return 1;
        }
        break;

    case TLS_ST_OK:
        if (mt == SSL3_MT_HELLO_REQUEST) {
            st->hand_state = TLS_ST_CR_HELLO_REQ;
            return 1;
        }
        break;
    }

 err:
    /* No valid transition found */
    if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
        BIO *rbio;

        /*
         * CCS messages don't have a message sequence number so this is probably
         * because of an out-of-order CCS. We'll just drop it.
         */
        s->init_num = 0;
        s->rwstate = SSL_READING;
        rbio = SSL_get_rbio(s);
        BIO_clear_retry_flags(rbio);
        BIO_set_retry_read(rbio);
        return 0;
    }
    SSLfatal_ntls(s, SSL3_AD_UNEXPECTED_MESSAGE,
             SSL_F_OSSL_STATEM_CLIENT_READ_TRANSITION_NTLS,
             SSL_R_UNEXPECTED_MESSAGE);
    return 0;
}

/*
 * ossl_statem_client_write_transition_ntls() works out what handshake state to
 * move to next when the client is writing messages to be sent to the server.
 */
WRITE_TRAN ossl_statem_client_write_transition_ntls(SSL *s)
{
    OSSL_STATEM *st = &s->statem;

    /*
     * Note that immediately before/after a ClientHello we don't know what
     * version we are going to negotiate yet, so we don't take this branch until
     * later
     */

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_OSSL_STATEM_CLIENT_WRITE_TRANSITION_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return WRITE_TRAN_ERROR;

    case TLS_ST_OK:
        if (!s->renegotiate) {
            /*
             * We haven't requested a renegotiation ourselves so we must have
             * received a message from the server. Better read it.
             */
            return WRITE_TRAN_FINISHED;
        }
        /* Renegotiation */
        /* fall thru */
    case TLS_ST_BEFORE:
        st->hand_state = TLS_ST_CW_CLNT_HELLO;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_CW_CLNT_HELLO:
        if (s->early_data_state == SSL_EARLY_DATA_CONNECTING) {
            /*
             * We are assuming this is a TLSv1.3 connection, although we haven't
             * actually selected a version yet.
             */
            if ((s->options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0)
                st->hand_state = TLS_ST_CW_CHANGE;
            else
                st->hand_state = TLS_ST_EARLY_DATA;
            return WRITE_TRAN_CONTINUE;
        }
        /*
         * No transition at the end of writing because we don't know what
         * we will be sent
         */
        return WRITE_TRAN_FINISHED;

    case TLS_ST_CR_SRVR_HELLO:
        /*
         * We only get here in TLSv1.3. We just received an HRR, so issue a
         * CCS unless middlebox compat mode is off, or we already issued one
         * because we did early data.
         */
        if ((s->options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0
                && s->early_data_state != SSL_EARLY_DATA_FINISHED_WRITING)
            st->hand_state = TLS_ST_CW_CHANGE;
        else
            st->hand_state = TLS_ST_CW_CLNT_HELLO;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_EARLY_DATA:
        return WRITE_TRAN_FINISHED;

    case TLS_ST_CR_SRVR_DONE:
        if (s->s3->tmp.cert_req)
            st->hand_state = TLS_ST_CW_CERT;
        else
            st->hand_state = TLS_ST_CW_KEY_EXCH;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_CW_CERT:
        st->hand_state = TLS_ST_CW_KEY_EXCH;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_CW_KEY_EXCH:
        /*
         * For TLS, cert_req is set to 2, so a cert chain of nothing is
         * sent, but no verify packet is sent
         */
        /*
         * XXX: For now, we do not support client authentication in ECDH
         * cipher suites with ECDH (rather than ECDSA) certificates. We
         * need to skip the certificate verify message when client's
         * ECDH public key is sent inside the client certificate.
         */
        if (s->s3->tmp.cert_req == 1) {
            st->hand_state = TLS_ST_CW_CERT_VRFY;
        } else {
            st->hand_state = TLS_ST_CW_CHANGE;
        }
        if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
            st->hand_state = TLS_ST_CW_CHANGE;
        }
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_CW_CERT_VRFY:
        st->hand_state = TLS_ST_CW_CHANGE;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_CW_CHANGE:
        if (s->hello_retry_request == SSL_HRR_PENDING) {
            st->hand_state = TLS_ST_CW_CLNT_HELLO;
        } else if (s->early_data_state == SSL_EARLY_DATA_CONNECTING) {
            st->hand_state = TLS_ST_EARLY_DATA;
        } else {
# if defined(OPENSSL_NO_NEXTPROTONEG)
            st->hand_state = TLS_ST_CW_FINISHED;
# else
            if (s->s3->npn_seen)
                st->hand_state = TLS_ST_CW_NEXT_PROTO;
            else
                st->hand_state = TLS_ST_CW_FINISHED;
# endif
        }
        return WRITE_TRAN_CONTINUE;

# if !defined(OPENSSL_NO_NEXTPROTONEG)
    case TLS_ST_CW_NEXT_PROTO:
        st->hand_state = TLS_ST_CW_FINISHED;
        return WRITE_TRAN_CONTINUE;
# endif

    case TLS_ST_CW_FINISHED:
        if (s->hit) {
            st->hand_state = TLS_ST_OK;
            return WRITE_TRAN_CONTINUE;
        } else {
            return WRITE_TRAN_FINISHED;
        }

    case TLS_ST_CR_FINISHED:
        if (s->hit) {
            st->hand_state = TLS_ST_CW_CHANGE;
            return WRITE_TRAN_CONTINUE;
        } else {
            st->hand_state = TLS_ST_OK;
            return WRITE_TRAN_CONTINUE;
        }

    case TLS_ST_CR_HELLO_REQ:
        /*
         * If we can renegotiate now then do so, otherwise wait for a more
         * convenient time.
         */
        if (ssl3_renegotiate_check(s, 1)) {
            if (!tls_setup_handshake_ntls(s)) {
                /* SSLfatal_ntls() already called */
                return WRITE_TRAN_ERROR;
            }
            st->hand_state = TLS_ST_CW_CLNT_HELLO;
            return WRITE_TRAN_CONTINUE;
        }
        st->hand_state = TLS_ST_OK;
        return WRITE_TRAN_CONTINUE;
    }
}

/*
 * Perform any pre work that needs to be done prior to sending a message from
 * the client to the server.
 */
WORK_STATE ossl_statem_client_pre_work_ntls(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* No pre work to be done */
        break;

    case TLS_ST_CW_CLNT_HELLO:
        s->shutdown = 0;
        break;

    case TLS_ST_CW_CHANGE:
        break;

    case TLS_ST_PENDING_EARLY_DATA_END:
        /*
         * If we've been called by SSL_do_handshake()/SSL_write(), or we did not
         * attempt to write early data before calling SSL_read() then we press
         * on with the handshake. Otherwise we pause here.
         */
        if (s->early_data_state == SSL_EARLY_DATA_FINISHED_WRITING
                || s->early_data_state == SSL_EARLY_DATA_NONE)
            return WORK_FINISHED_CONTINUE;
        /* Fall through */

    case TLS_ST_EARLY_DATA:
        return tls_finish_handshake_ntls(s, wst, 0, 1);

    case TLS_ST_OK:
        /* Calls SSLfatal_ntls() as required */
        return tls_finish_handshake_ntls(s, wst, 1, 1);
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Perform any work that needs to be done after sending a message from the
 * client to the server.
 */
WORK_STATE ossl_statem_client_post_work_ntls(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    s->init_num = 0;

    switch (st->hand_state) {
    default:
        /* No post work to be done */
        break;

    case TLS_ST_CW_CLNT_HELLO:
        if (s->early_data_state == SSL_EARLY_DATA_CONNECTING
                && s->max_early_data > 0) {
            /*
             * We haven't selected TLSv1.3 yet so we don't call the change
             * cipher state function associated with the SSL_METHOD. Instead
             * we call tls13_change_cipher_state() directly.
             */
            if ((s->options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) == 0) {
                if (!tls13_change_cipher_state(s,
                            SSL3_CC_EARLY | SSL3_CHANGE_CIPHER_CLIENT_WRITE)) {
                    /* SSLfatal_ntls() already called */
                    return WORK_ERROR;
                }
            }
            /* else we're in compat mode so we delay flushing until after CCS */
        } else if (!statem_flush_ntls(s)) {
            return WORK_MORE_A;
        }

        break;

    case TLS_ST_CW_END_OF_EARLY_DATA:
        /*
         * We set the enc_write_ctx back to NULL because we may end up writing
         * in cleartext again if we get a HelloRetryRequest from the server.
         */
        EVP_CIPHER_CTX_free(s->enc_write_ctx);
        s->enc_write_ctx = NULL;
        break;

    case TLS_ST_CW_KEY_EXCH:
        if (tls_client_key_exchange_post_work_ntls(s) == 0) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }
        break;

    case TLS_ST_CW_CHANGE:
        if (s->hello_retry_request == SSL_HRR_PENDING)
            break;
        if (s->early_data_state == SSL_EARLY_DATA_CONNECTING
                    && s->max_early_data > 0) {
            /*
             * We haven't selected TLSv1.3 yet so we don't call the change
             * cipher state function associated with the SSL_METHOD. Instead
             * we call tls13_change_cipher_state() directly.
             */
            if (!tls13_change_cipher_state(s,
                        SSL3_CC_EARLY | SSL3_CHANGE_CIPHER_CLIENT_WRITE))
                return WORK_ERROR;
            break;
        }
        s->session->cipher = s->s3->tmp.new_cipher;
        s->session->compress_meth = 0;

        if (!s->method->ssl3_enc->setup_key_block(s)) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }

        if (!s->method->ssl3_enc->change_cipher_state(s,
                                          SSL3_CHANGE_CIPHER_CLIENT_WRITE)) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }

        break;

    case TLS_ST_CW_FINISHED:
        if (statem_flush_ntls(s) != 1)
            return WORK_MORE_B;
        break;

    case TLS_ST_CW_KEY_UPDATE:
        if (statem_flush_ntls(s) != 1)
            return WORK_MORE_A;
        if (!tls13_update_key(s, 1)) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }
        break;
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Get the message construction function and message type for sending from the
 * client
 *
 * Valid return values are:
 *   1: Success
 *   0: Error
 */
int ossl_statem_client_construct_message_ntls(SSL *s, WPACKET *pkt,
                                         confunc_f *confunc, int *mt)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_OSSL_STATEM_CLIENT_CONSTRUCT_MESSAGE_NTLS,
                 SSL_R_BAD_HANDSHAKE_STATE);
        return 0;

    case TLS_ST_CW_CHANGE:
        *confunc = tls_construct_change_cipher_spec_ntls;
        *mt = SSL3_MT_CHANGE_CIPHER_SPEC;
        break;

    case TLS_ST_CW_CLNT_HELLO:
        *confunc = tls_construct_client_hello_ntls;
        *mt = SSL3_MT_CLIENT_HELLO;
        break;

    case TLS_ST_CW_END_OF_EARLY_DATA:
        *confunc = tls_construct_end_of_early_data_ntls;
        *mt = SSL3_MT_END_OF_EARLY_DATA;
        break;

    case TLS_ST_PENDING_EARLY_DATA_END:
        *confunc = NULL;
        *mt = SSL3_MT_DUMMY;
        break;

    case TLS_ST_CW_CERT:
        *confunc = tls_construct_client_certificate_ntls;
        *mt = SSL3_MT_CERTIFICATE;
        break;

    case TLS_ST_CW_KEY_EXCH:
        *confunc = ntls_construct_client_key_exchange_ntls;
        *mt = SSL3_MT_CLIENT_KEY_EXCHANGE;
        break;

    case TLS_ST_CW_CERT_VRFY:
        *confunc = ntls_construct_cert_verify_ntls;
        *mt = SSL3_MT_CERTIFICATE_VERIFY;
        break;

# if !defined(OPENSSL_NO_NEXTPROTONEG)
    case TLS_ST_CW_NEXT_PROTO:
        *confunc = tls_construct_next_proto_ntls;
        *mt = SSL3_MT_NEXT_PROTO;
        break;
# endif
    case TLS_ST_CW_FINISHED:
        *confunc = tls_construct_finished_ntls;
        *mt = SSL3_MT_FINISHED;
        break;

    case TLS_ST_CW_KEY_UPDATE:
        *confunc = tls_construct_key_update_ntls;
        *mt = SSL3_MT_KEY_UPDATE;
        break;
    }

    return 1;
}

/*
 * Returns the maximum allowed length for the current message that we are
 * reading. Excludes the message header.
 */
size_t ossl_statem_client_max_message_size_ntls(SSL *s)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        return 0;

    case TLS_ST_CR_SRVR_HELLO:
        return SERVER_HELLO_MAX_LENGTH;

    case TLS_ST_CR_CERT:
        return s->max_cert_list;

    case TLS_ST_CR_CERT_VRFY:
        return SSL3_RT_MAX_PLAIN_LENGTH;

    case TLS_ST_CR_CERT_STATUS:
        return SSL3_RT_MAX_PLAIN_LENGTH;

    case TLS_ST_CR_KEY_EXCH:
        return SERVER_KEY_EXCH_MAX_LENGTH;

    case TLS_ST_CR_CERT_REQ:
        /*
         * Set to s->max_cert_list for compatibility with previous releases. In
         * practice these messages can get quite long if servers are configured
         * to provide a long list of acceptable CAs
         */
        return s->max_cert_list;

    case TLS_ST_CR_SRVR_DONE:
        return SERVER_HELLO_DONE_MAX_LENGTH;

    case TLS_ST_CR_CHANGE:
        return CCS_MAX_LENGTH;

    case TLS_ST_CR_SESSION_TICKET:
        return SSL3_RT_MAX_PLAIN_LENGTH;

    case TLS_ST_CR_FINISHED:
        return FINISHED_MAX_LENGTH;

    case TLS_ST_CR_ENCRYPTED_EXTENSIONS:
        return ENCRYPTED_EXTENSIONS_MAX_LENGTH;

    case TLS_ST_CR_KEY_UPDATE:
        return KEY_UPDATE_MAX_LENGTH;
    }
}

/*
 * Process a message that the client has been received from the server.
 */
MSG_PROCESS_RETURN ossl_statem_client_process_message_ntls(SSL *s, PACKET *pkt)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_OSSL_STATEM_CLIENT_PROCESS_MESSAGE_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;

    case TLS_ST_CR_SRVR_HELLO:
        return tls_process_server_hello_ntls(s, pkt);

    case TLS_ST_CR_CERT:
        return tls_process_server_certificate_ntls(s, pkt);

    case TLS_ST_CR_CERT_VRFY:
        return tls_process_cert_verify_ntls(s, pkt);

    case TLS_ST_CR_CERT_STATUS:
        return tls_process_cert_status_ntls(s, pkt);

    case TLS_ST_CR_KEY_EXCH:
        return ntls_process_server_key_exchange_ntls(s, pkt);


    case TLS_ST_CR_CERT_REQ:
        return tls_process_certificate_request_ntls(s, pkt);

    case TLS_ST_CR_SRVR_DONE:
        return tls_process_server_done_ntls(s, pkt);

    case TLS_ST_CR_CHANGE:
        return tls_process_change_cipher_spec_ntls(s, pkt);

    case TLS_ST_CR_SESSION_TICKET:
        return tls_process_new_session_ticket_ntls(s, pkt);

    case TLS_ST_CR_FINISHED:
        return tls_process_finished_ntls(s, pkt);

    case TLS_ST_CR_HELLO_REQ:
        return tls_process_hello_req_ntls(s, pkt);

    case TLS_ST_CR_ENCRYPTED_EXTENSIONS:
        return tls_process_encrypted_extensions(s, pkt);

    case TLS_ST_CR_KEY_UPDATE:
        return tls_process_key_update_ntls(s, pkt);
    }
}

/*
 * Perform any further processing required following the receipt of a message
 * from the server
 */
WORK_STATE ossl_statem_client_post_process_message_ntls(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_OSSL_STATEM_CLIENT_POST_PROCESS_MESSAGE_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return WORK_ERROR;

    case TLS_ST_CR_CERT_VRFY:
    case TLS_ST_CR_CERT_REQ:
        return tls_prepare_client_certificate_ntls(s, wst);
    }
}

int tls_construct_client_hello_ntls(SSL *s, WPACKET *pkt)
{
    unsigned char *p;
    size_t sess_id_len;
    int i, protverr;
    SSL_SESSION *sess = s->session;
    unsigned char *session_id;

    /* Work out what SSL/TLS version to use */
    protverr = ssl_set_client_hello_version_ntls(s);
    if (protverr != 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CLIENT_HELLO_NTLS,
                 protverr);
        return 0;
    }

    if (sess == NULL
            || !ssl_version_supported_ntls(s, sess->ssl_version, NULL)
            || !SSL_SESSION_is_resumable(sess)) {
        if (s->hello_retry_request == SSL_HRR_NONE
                && !ssl_get_new_session(s, 0)) {
            /* SSLfatal_ntls() already called */
            return 0;
        }
    }
    /* else use the pre-loaded session */

    p = s->s3->client_random;
    i = (s->hello_retry_request == SSL_HRR_NONE);

    if (i && ssl_fill_hello_random(s, 0, p, sizeof(s->s3->client_random),
                                   DOWNGRADE_NONE) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CLIENT_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*-
     * version indicates the negotiated version: for example from
     * an SSLv2/v3 compatible client hello). The client_version
     * field is the maximum version we permit and it is also
     * used in RSA encrypted premaster secrets. Some servers can
     * choke if we initially report a higher version then
     * renegotiate to a lower one in the premaster secret. This
     * didn't happen with TLS 1.0 as most servers supported it
     * but it can with TLS 1.1 or later if the server only supports
     * 1.0.
     *
     * Possible scenario with previous logic:
     *      1. Client hello indicates TLS 1.2
     *      2. Server hello says TLS 1.0
     *      3. RSA encrypted premaster secret uses 1.2.
     *      4. Handshake proceeds using TLS 1.0.
     *      5. Server sends hello request to renegotiate.
     *      6. Client hello indicates TLS v1.0 as we now
     *         know that is maximum server supports.
     *      7. Server chokes on RSA encrypted premaster secret
     *         containing version 1.0.
     *
     * For interoperability it should be OK to always use the
     * maximum version we support in client hello and then rely
     * on the checking of version to ensure the servers isn't
     * being inconsistent: for example initially negotiating with
     * TLS 1.0 and renegotiating with TLS 1.2. We do this by using
     * client_version in client hello and not resetting it to
     * the negotiated version.
     *
     * For TLS 1.3 we always set the ClientHello version to 1.2 and rely on the
     * supported_versions extension for the real supported versions.
     */
    if (!WPACKET_put_bytes_u16(pkt, s->client_version)
            || !WPACKET_memcpy(pkt, s->s3->client_random, SSL3_RANDOM_SIZE)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CLIENT_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Session ID */
    session_id = s->session->session_id;
    if (s->new_session || s->session->ssl_version == TLS1_3_VERSION) {
        if (s->version == TLS1_3_VERSION
                && (s->options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0) {
            sess_id_len = sizeof(s->tmp_session_id);
            s->tmp_session_id_len = sess_id_len;
            session_id = s->tmp_session_id;
            if (s->hello_retry_request == SSL_HRR_NONE
                    && RAND_bytes(s->tmp_session_id, sess_id_len) <= 0) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_CONSTRUCT_CLIENT_HELLO_NTLS,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        } else {
            sess_id_len = 0;
        }
    } else {
        assert(s->session->session_id_length <= sizeof(s->session->session_id));
        sess_id_len = s->session->session_id_length;
        if (s->version == TLS1_3_VERSION) {
            s->tmp_session_id_len = sess_id_len;
            memcpy(s->tmp_session_id, s->session->session_id, sess_id_len);
        }
    }
    if (!WPACKET_start_sub_packet_u8(pkt)
            || (sess_id_len != 0 && !WPACKET_memcpy(pkt, session_id,
                                                    sess_id_len))
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CLIENT_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Ciphers supported */
    if (!WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CLIENT_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), pkt)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }
    if (!WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CLIENT_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* COMPRESSION */
    if (!WPACKET_start_sub_packet_u8(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CLIENT_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Add the NULL method */
    if (!WPACKET_put_bytes_u8(pkt, 0) || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CLIENT_HELLO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* TLS extensions */
    if (!tls_construct_extensions_ntls(s, pkt, SSL_EXT_CLIENT_HELLO, NULL, 0)) {
        /* SSLfatal() already called */
        return 0;
    }

    return 1;
}

static int set_client_ciphersuite(SSL *s, const unsigned char *cipherchars)
{
    STACK_OF(SSL_CIPHER) *sk;
    const SSL_CIPHER *c;
    int i;

    c = ssl_get_cipher_by_char(s, cipherchars, 0);
    if (c == NULL) {
        /* unknown cipher */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_SET_CLIENT_CIPHERSUITE,
                 SSL_R_UNKNOWN_CIPHER_RETURNED);
        return 0;
    }
    /*
     * If it is a disabled cipher we either didn't send it in client hello,
     * or it's not allowed for the selected protocol. So we return an error.
     */
    if (ssl_cipher_disabled(s, c, SSL_SECOP_CIPHER_CHECK, 1)) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_SET_CLIENT_CIPHERSUITE,
                 SSL_R_WRONG_CIPHER_RETURNED);
        return 0;
    }

    sk = ssl_get_ciphers_by_id(s);
    i = sk_SSL_CIPHER_find(sk, c);
    if (i < 0) {
        /* we did not say we would use this cipher */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_SET_CLIENT_CIPHERSUITE,
                 SSL_R_WRONG_CIPHER_RETURNED);
        return 0;
    }

    /*
     * Depending on the session caching (internal/external), the cipher
     * and/or cipher_id values may not be set. Make sure that cipher_id is
     * set and use it for comparison.
     */
    if (s->session->cipher != NULL)
        s->session->cipher_id = s->session->cipher->id;
    if (s->hit && (s->session->cipher_id != c->id)) {
        /*
            * Prior to TLSv1.3 resuming a session always meant using the same
            * ciphersuite.
            */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_SET_CLIENT_CIPHERSUITE,
                    SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED);
        return 0;
    }
    s->s3->tmp.new_cipher = c;

    return 1;
}

MSG_PROCESS_RETURN tls_process_server_hello_ntls(SSL *s, PACKET *pkt)
{
    PACKET session_id, extpkt;
    size_t session_id_len;
    const unsigned char *cipherchars;
    int hrr = 0;
    unsigned int compression;
    unsigned int sversion;
    unsigned int context;
    RAW_EXTENSION *extensions = NULL;

    if (!PACKET_get_net_2(pkt, &sversion)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    /* load the server random */
    if (s->version == TLS1_3_VERSION
            && sversion == TLS1_2_VERSION
            && PACKET_remaining(pkt) >= SSL3_RANDOM_SIZE
            && memcmp(hrrrandom_ntls, PACKET_data(pkt), SSL3_RANDOM_SIZE) == 0) {
        s->hello_retry_request = SSL_HRR_PENDING;
        hrr = 1;
        if (!PACKET_forward(pkt, SSL3_RANDOM_SIZE)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                     SSL_R_LENGTH_MISMATCH);
            goto err;
        }
    } else {
        if (!PACKET_copy_bytes(pkt, s->s3->server_random, SSL3_RANDOM_SIZE)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                     SSL_R_LENGTH_MISMATCH);
            goto err;
        }
    }

    /* Get the session-id. */
    if (!PACKET_get_length_prefixed_1(pkt, &session_id)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        goto err;
    }
    session_id_len = PACKET_remaining(&session_id);
    if (session_id_len > sizeof(s->session->session_id)
        || session_id_len > SSL3_SESSION_ID_SIZE) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                 SSL_R_SSL3_SESSION_ID_TOO_LONG);
        goto err;
    }

    if (!PACKET_get_bytes(pkt, &cipherchars, TLS_CIPHER_LEN)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    if (!PACKET_get_1(pkt, &compression)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    /* TLS extensions */
    if (PACKET_remaining(pkt) == 0 && !hrr) {
        PACKET_null_init(&extpkt);
    } else if (!PACKET_as_length_prefixed_2(pkt, &extpkt)
               || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                 SSL_R_BAD_LENGTH);
        goto err;
    }

    if (!hrr) {
        if (!tls_collect_extensions_ntls(s, &extpkt,
                                    SSL_EXT_TLS1_2_SERVER_HELLO
                                    | SSL_EXT_TLS1_3_SERVER_HELLO,
                                    &extensions, NULL, 1)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }

        if (!ssl_choose_client_version_ntls(s, sversion, extensions)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    }

    if (hrr) {
        if (compression != 0) {
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                     SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                     SSL_R_INVALID_COMPRESSION_ALGORITHM);
            goto err;
        }

        if (session_id_len != s->tmp_session_id_len
                || memcmp(PACKET_data(&session_id), s->tmp_session_id,
                          session_id_len) != 0) {
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                     SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS, SSL_R_INVALID_SESSION_ID);
            goto err;
        }
    }

    if (hrr) {
        if (!set_client_ciphersuite(s, cipherchars)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }

        return tls_process_as_hello_retry_request(s, &extpkt);
    }

    /*
     * Now we have chosen the version we need to check again that the extensions
     * are appropriate for this version.
     */
    context = SSL_EXT_TLS1_2_SERVER_HELLO;
    if (!tls_validate_all_contexts_ntls(s, context, extensions)) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                 SSL_R_BAD_EXTENSION);
        goto err;
    }

    s->hit = 0;

    /*
        * Check if we can resume the session based on external pre-shared
        * secret. EAP-FAST (RFC 4851) supports two types of session resumption.
        * Resumption based on server-side state works with session IDs.
        * Resumption based on pre-shared Protected Access Credentials (PACs)
        * works by overriding the SessionTicket extension at the application
        * layer, and does not send a session ID. (We do not know whether
        * EAP-FAST servers would honour the session ID.) Therefore, the session
        * ID alone is not a reliable indicator of session resumption, so we
        * first check if we can resume, and later peek at the next handshake
        * message to see if the server wants to resume.
        */
    if (s->version >= TLS1_VERSION
            && s->ext.session_secret_cb != NULL && s->session->ext.tick) {
        const SSL_CIPHER *pref_cipher = NULL;
        /*
            * s->session->master_key_length is a size_t, but this is an int for
            * backwards compat reasons
            */
        int master_key_length;
        master_key_length = sizeof(s->session->master_key);
        if (s->ext.session_secret_cb(s, s->session->master_key,
                                        &master_key_length,
                                        NULL, &pref_cipher,
                                        s->ext.session_secret_cb_arg)
                    && master_key_length > 0) {
            s->session->master_key_length = master_key_length;
            s->session->cipher = pref_cipher ?
                pref_cipher : ssl_get_cipher_by_char(s, cipherchars, 0);
        } else {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                        SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if (session_id_len != 0
            && session_id_len == s->session->session_id_length
            && memcmp(PACKET_data(&session_id), s->session->session_id,
                        session_id_len) == 0)
        s->hit = 1;

    if (s->hit) {
        if (s->sid_ctx_length != s->session->sid_ctx_length
                || memcmp(s->session->sid_ctx, s->sid_ctx, s->sid_ctx_length)) {
            /* actually a client application bug */
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                     SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                     SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT);
            goto err;
        }
    } else {
        /*
         * If we were trying for session-id reuse but the server
         * didn't resume, make a new SSL_SESSION.
         * In the case of EAP-FAST and PAC, we do not send a session ID,
         * so the PAC-based session secret is always preserved. It'll be
         * overwritten if the server refuses resumption.
         */
        if (s->session->session_id_length > 0) {
            tsan_counter(&s->session_ctx->stats.sess_miss);
            if (!ssl_get_new_session(s, 0)) {
                /* SSLfatal_ntls() already called */
                goto err;
            }
        }

        s->session->ssl_version = s->version;
        /*
         * In TLSv1.2 and below we save the session id we were sent so we can
         * resume it later. In TLSv1.3 the session id we were sent is just an
         * echo of what we originally sent in the ClientHello and should not be
         * used for resumption.
         */
        s->session->session_id_length = session_id_len;
        /* session_id_len could be 0 */
        if (session_id_len > 0)
            memcpy(s->session->session_id, PACKET_data(&session_id),
                    session_id_len);
    }

    /* Session version and negotiated protocol version should match */
    if (s->version != s->session->ssl_version) {
        SSLfatal_ntls(s, SSL_AD_PROTOCOL_VERSION, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                 SSL_R_SSL_SESSION_VERSION_MISMATCH);
        goto err;
    }
    /*
     * Now that we know the version, update the check to see if it's an allowed
     * version.
     */
    s->s3->tmp.min_ver = s->version;
    s->s3->tmp.max_ver = s->version;

    if (!set_client_ciphersuite(s, cipherchars)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    if (compression != 0) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                 SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
        goto err;
    }
    /*
     * If compression is disabled we'd better not try to resume a session
     * using compression.
     */
    if (s->session->compress_meth != 0) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, SSL_F_TLS_PROCESS_SERVER_HELLO_NTLS,
                 SSL_R_INCONSISTENT_COMPRESSION);
        goto err;
    }


    if (!tls_parse_all_extensions_ntls(s, context, extensions, NULL, 0, 1)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    /*
     * In TLSv1.3 we have some post-processing to change cipher state, otherwise
     * we're done with this message
     */
    OPENSSL_free(extensions);
    return MSG_PROCESS_CONTINUE_READING;
 err:
    OPENSSL_free(extensions);
    return MSG_PROCESS_ERROR;
}

static MSG_PROCESS_RETURN tls_process_as_hello_retry_request(SSL *s,
                                                             PACKET *extpkt)
{
    RAW_EXTENSION *extensions = NULL;

    /*
     * If we were sending early_data then the enc_write_ctx is now invalid and
     * should not be used.
     */
    EVP_CIPHER_CTX_free(s->enc_write_ctx);
    s->enc_write_ctx = NULL;

    if (!tls_collect_extensions_ntls(s, extpkt, SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST,
                                &extensions, NULL, 1)
            || !tls_parse_all_extensions_ntls(s, SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST,
                                         extensions, NULL, 0, 1)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    OPENSSL_free(extensions);
    extensions = NULL;

    if (s->ext.tls13_cookie_len == 0
# if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH)
        && s->s3->tmp.pkey != NULL
# endif
        ) {
        /*
         * We didn't receive a cookie or a new key_share so the next
         * ClientHello will not change
         */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                 SSL_F_TLS_PROCESS_AS_HELLO_RETRY_REQUEST,
                 SSL_R_NO_CHANGE_FOLLOWING_HRR);
        goto err;
    }

    /*
     * Re-initialise the Transcript Hash. We're going to prepopulate it with
     * a synthetic message_hash in place of ClientHello1.
     */
    if (!create_synthetic_message_hash_ntls(s, NULL, 0, NULL, 0)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    /*
     * Add this message to the Transcript Hash. Normally this is done
     * automatically prior to the message processing stage. However due to the
     * need to create the synthetic message hash, we defer that step until now
     * for HRR messages.
     */
    if (!ssl3_finish_mac(s, (unsigned char *)s->init_buf->data,
                                s->init_num + SSL3_HM_HEADER_LENGTH)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    return MSG_PROCESS_FINISHED_READING;
 err:
    OPENSSL_free(extensions);
    return MSG_PROCESS_ERROR;
}

MSG_PROCESS_RETURN tls_process_server_certificate_ntls(SSL *s, PACKET *pkt)
{
    int i, j;
    MSG_PROCESS_RETURN ret = MSG_PROCESS_ERROR;
    unsigned long cert_list_len, cert_len;
    X509 *x = NULL;
    const unsigned char *certstart, *certbytes;
    STACK_OF(X509) *sk = NULL;
    EVP_PKEY *pkey = NULL;
    size_t chainidx, certidx;
    unsigned int context = 0;
    const SSL_CERT_LOOKUP *clu;

    if ((sk = sk_X509_new_null()) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (context != 0
            || !PACKET_get_net_3(pkt, &cert_list_len)
            || PACKET_remaining(pkt) != cert_list_len
            || PACKET_remaining(pkt) == 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        goto err;
    }
    for (chainidx = 0; PACKET_remaining(pkt); chainidx++) {
        if (!PACKET_get_net_3(pkt, &cert_len)
            || !PACKET_get_bytes(pkt, &certbytes, cert_len)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                     SSL_R_CERT_LENGTH_MISMATCH);
            goto err;
        }

        certstart = certbytes;
        x = d2i_X509(NULL, (const unsigned char **)&certbytes, cert_len);
        if (x == NULL) {
            SSLfatal_ntls(s, SSL_AD_BAD_CERTIFICATE,
                     SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS, ERR_R_ASN1_LIB);
            goto err;
        }
        if (certbytes != (certstart + cert_len)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                     SSL_R_CERT_LENGTH_MISMATCH);
            goto err;
        }

        if (!sk_X509_push(sk, x)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                     ERR_R_MALLOC_FAILURE);
            goto err;
        }
        x = NULL;
    }

# ifndef OPENSSL_NO_SM2

    {
        int n = sk_X509_num(sk) - 1;

        while (n >= 0) {
            X509 *cert = sk_X509_value(sk, n);
            ASN1_OCTET_STRING *sm2_id;
            sm2_id = ASN1_OCTET_STRING_new();

            if (sm2_id == NULL) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                         ERR_R_MALLOC_FAILURE);
                goto err;
            }

            if (!ASN1_OCTET_STRING_set(sm2_id,
                                       (const unsigned char *)CERTVRIFY_SM2_ID,
                                       CERTVRIFY_SM2_ID_LEN)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                         ERR_R_INTERNAL_ERROR);
                ASN1_OCTET_STRING_free(sm2_id);
                goto err;
            }

            X509_set0_sm2_id(cert, sm2_id);
            n--;
        }

    }

# endif

    if (sk_X509_num(sk) >= 2) {
        for (j = 0; j < 2; j++) {
            if (j == 0)
                sk_X509_push(sk, sk_X509_shift(sk));
            if (j == 1)
                sk_X509_unshift(sk, sk_X509_pop(sk));

            i = ssl_verify_cert_chain(s, sk);

            /*
             * The documented interface is that SSL_VERIFY_PEER should be set in order
             * for client side verification of the server certificate to take place.
             * However, historically the code has only checked that *any* flag is set
             * to cause server verification to take place. Use of the other flags makes
             * no sense in client mode. An attempt to clean up the semantics was
             * reverted because at least one application *only* set
             * SSL_VERIFY_FAIL_IF_NO_PEER_CERT. Prior to the clean up this still caused
             * server verification to take place, after the clean up it silently did
             * nothing. SSL_CTX_set_verify()/SSL_set_verify() cannot validate the flags
             * sent to them because they are void functions. Therefore, we now use the
             * (less clean) historic behaviour of performing validation if any flag is
             * set. The *documented* interface remains the same.
             */
            if (s->verify_mode != SSL_VERIFY_NONE && i <= 0) {
                SSLfatal_ntls(s, ssl_x509err2alert_ntls(s->verify_result),
                              SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                              SSL_R_CERTIFICATE_VERIFY_FAILED);
                goto err;
            }

            ERR_clear_error();          /* but we keep s->verify_result */
            if (i > 1) {
                SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                              SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS, i);
                goto err;
            }
        }
    } else {
        if (s->verify_mode != SSL_VERIFY_NONE) {
            SSLfatal_ntls(s, ssl_x509err2alert_ntls(s->verify_result),
                          SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                          SSL_R_CERTIFICATE_VERIFY_FAILED);
            goto err;
        }
    }

    s->session->peer_chain = sk;
    /*
     * Inconsistency alert: cert_chain does include the peer's certificate,
     * which we don't include in statem_srvr.c
     */
    x = sk_X509_value(sk, 0);
    sk = NULL;

    pkey = X509_get0_pubkey(x);

    if (pkey == NULL || EVP_PKEY_missing_parameters(pkey)) {
        x = NULL;
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                 SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS);
        goto err;
    }

    if ((clu = ssl_cert_lookup_by_pkey(pkey, &certidx)) == NULL) {
        x = NULL;
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                 SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                 SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        goto err;
    }
    /*
     * Check certificate type is consistent with ciphersuite. For TLS 1.3
     * skip check since TLS 1.3 ciphersuites can be used with any certificate
     * type.
     */
    if ((clu->amask & s->s3->tmp.new_cipher->algorithm_auth) == 0) {
        x = NULL;
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                    SSL_F_TLS_PROCESS_SERVER_CERTIFICATE_NTLS,
                    SSL_R_WRONG_CERTIFICATE_TYPE);
        goto err;
    }
    s->session->peer_type = certidx;

    X509_free(s->session->peer);
    X509_up_ref(x);
    s->session->peer = x;
    s->session->verify_result = s->verify_result;
    x = NULL;

    ret = MSG_PROCESS_CONTINUE_READING;

 err:
    X509_free(x);
    sk_X509_pop_free(sk, X509_free);
    return ret;
}

static int tls_process_ske_psk_preamble(SSL *s, PACKET *pkt)
{
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_SKE_PSK_PREAMBLE,
             ERR_R_INTERNAL_ERROR);
    return 0;

}

static int tls_process_ske_dhe(SSL *s, PACKET *pkt, EVP_PKEY **pkey)
{
# ifndef OPENSSL_NO_DH
    PACKET prime, generator, pub_key;
    EVP_PKEY *peer_tmp = NULL;

    DH *dh = NULL;
    BIGNUM *p = NULL, *g = NULL, *bnpub_key = NULL;

    int check_bits = 0;

    if (!PACKET_get_length_prefixed_2(pkt, &prime)
        || !PACKET_get_length_prefixed_2(pkt, &generator)
        || !PACKET_get_length_prefixed_2(pkt, &pub_key)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SKE_DHE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    peer_tmp = EVP_PKEY_new();
    dh = DH_new();

    if (peer_tmp == NULL || dh == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_SKE_DHE,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* TODO(size_t): Convert these calls */
    p = BN_bin2bn(PACKET_data(&prime), (int)PACKET_remaining(&prime), NULL);
    g = BN_bin2bn(PACKET_data(&generator), (int)PACKET_remaining(&generator),
                  NULL);
    bnpub_key = BN_bin2bn(PACKET_data(&pub_key),
                          (int)PACKET_remaining(&pub_key), NULL);
    if (p == NULL || g == NULL || bnpub_key == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_SKE_DHE,
                 ERR_R_BN_LIB);
        goto err;
    }

    /* test non-zero pubkey */
    if (BN_is_zero(bnpub_key)) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PROCESS_SKE_DHE,
                 SSL_R_BAD_DH_VALUE);
        goto err;
    }

    if (!DH_set0_pqg(dh, p, NULL, g)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_SKE_DHE,
                 ERR_R_BN_LIB);
        goto err;
    }
    p = g = NULL;

    if (DH_check_params(dh, &check_bits) == 0 || check_bits != 0) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PROCESS_SKE_DHE,
                 SSL_R_BAD_DH_VALUE);
        goto err;
    }

    if (!DH_set0_key(dh, bnpub_key, NULL)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_SKE_DHE,
                 ERR_R_BN_LIB);
        goto err;
    }
    bnpub_key = NULL;

    if (!ssl_security(s, SSL_SECOP_TMP_DH, DH_security_bits(dh), 0, dh)) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, SSL_F_TLS_PROCESS_SKE_DHE,
                 SSL_R_DH_KEY_TOO_SMALL);
        goto err;
    }

    if (EVP_PKEY_assign_DH(peer_tmp, dh) == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_SKE_DHE,
                 ERR_R_EVP_LIB);
        goto err;
    }

    s->s3->peer_tmp = peer_tmp;

    /*
     * FIXME: This makes assumptions about which ciphersuites come with
     * public keys. We should have a less ad-hoc way of doing this
     */
    if (s->s3->tmp.new_cipher->algorithm_auth & (SSL_aRSA | SSL_aDSS))
        *pkey = X509_get0_pubkey(s->session->peer);
    /* else anonymous DH, so no certificate or pkey. */

    return 1;

 err:
    BN_free(p);
    BN_free(g);
    BN_free(bnpub_key);
    DH_free(dh);
    EVP_PKEY_free(peer_tmp);

    return 0;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_SKE_DHE,
             ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int tls_process_ske_ecdhe(SSL *s, PACKET *pkt, EVP_PKEY **pkey)
{
# ifndef OPENSSL_NO_EC
    PACKET encoded_pt;
    unsigned int curve_type, curve_id;

    /*
     * Extract elliptic curve parameters and the server's ephemeral ECDH
     * public key. We only support named (not generic) curves and
     * ECParameters in this case is just three bytes.
     */
    if (!PACKET_get_1(pkt, &curve_type) || !PACKET_get_net_2(pkt, &curve_id)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SKE_ECDHE,
                 SSL_R_LENGTH_TOO_SHORT);
        return 0;
    }
    /*
     * Check curve is named curve type and one of our preferences, if not
     * server has sent an invalid curve.
     */
    if (curve_type != NAMED_CURVE_TYPE
            || !tls1_check_group_id(s, curve_id, 1)) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PROCESS_SKE_ECDHE,
                 SSL_R_WRONG_CURVE);
        return 0;
    }

    if ((s->s3->peer_tmp = ssl_generate_param_group(curve_id)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_SKE_ECDHE,
                 SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
        return 0;
    }

    if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SKE_ECDHE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if (!EVP_PKEY_set1_tls_encodedpoint(s->s3->peer_tmp,
                                        PACKET_data(&encoded_pt),
                                        PACKET_remaining(&encoded_pt))) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLS_PROCESS_SKE_ECDHE,
                 SSL_R_BAD_ECPOINT);
        return 0;
    }

    /*
     * The ECC/TLS specification does not mention the use of DSA to sign
     * ECParameters in the server key exchange message. We do support RSA
     * and ECDSA.
     */
    if (s->s3->tmp.new_cipher->algorithm_auth & SSL_aECDSA)
        *pkey = X509_get0_pubkey(s->session->peer);
    else if (s->s3->tmp.new_cipher->algorithm_auth & SSL_aSM2)
        *pkey = X509_get0_pubkey(s->session->peer);
    else if (s->s3->tmp.new_cipher->algorithm_auth & SSL_aRSA)
        *pkey = X509_get0_pubkey(s->session->peer);
    /* else anonymous ECDH, so no certificate or pkey. */

    return 1;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_SKE_ECDHE,
             ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

MSG_PROCESS_RETURN tls_process_key_exchange_ntls(SSL *s, PACKET *pkt)
{
    long alg_k;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    PACKET save_param_start, signature;

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    save_param_start = *pkt;

# if !defined(OPENSSL_NO_EC) || !defined(OPENSSL_NO_DH)
    EVP_PKEY_free(s->s3->peer_tmp);
    s->s3->peer_tmp = NULL;
# endif

    if (alg_k & SSL_PSK) {
        if (!tls_process_ske_psk_preamble(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    }

    /* Nothing else to do for plain PSK or RSAPSK */
    if (alg_k & (SSL_kDHE | SSL_kDHEPSK)) {
        if (!tls_process_ske_dhe(s, pkt, &pkey)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & (SSL_kECDHE | SSL_kECDHEPSK)) {
        if (!tls_process_ske_ecdhe(s, pkt, &pkey)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k) {
        SSLfatal_ntls(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                 SSL_R_UNEXPECTED_MESSAGE);
        goto err;
    }

    /* if it was signed, check the signature */
    if (pkey != NULL) {
        PACKET params;
        int maxsig;
        const EVP_MD *md = NULL;
        unsigned char *tbs;
        size_t tbslen;
        int rv;

        /*
         * |pkt| now points to the beginning of the signature, so the difference
         * equals the length of the parameters.
         */
        if (!PACKET_get_sub_packet(&save_param_start, &params,
                                   PACKET_remaining(&save_param_start) -
                                   PACKET_remaining(pkt))) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (SSL_USE_SIGALGS(s)) {
            unsigned int sigalg;

            if (!PACKET_get_net_2(pkt, &sigalg)) {
                SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                         SSL_R_LENGTH_TOO_SHORT);
                goto err;
            }
            if (tls12_check_peer_sigalg(s, sigalg, pkey) <=0) {
                /* SSLfatal_ntls() already called */
                goto err;
            }
        } else if (!tls1_set_peer_legacy_sigalg(s, pkey)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (!tls1_lookup_md(s->s3->tmp.peer_sigalg, &md)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }
# ifdef SSL_DEBUG
        if (SSL_USE_SIGALGS(s))
            fprintf(stderr, "USING TLSv1.2 HASH %s\n",
                    md == NULL ? "n/a" : EVP_MD_name(md));
# endif

        if (!PACKET_get_length_prefixed_2(pkt, &signature)
            || PACKET_remaining(pkt) != 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                     SSL_R_LENGTH_MISMATCH);
            goto err;
        }
        maxsig = EVP_PKEY_size(pkey);
        if (maxsig < 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                     ERR_R_INTERNAL_ERROR);
            goto err;
        }

        /*
         * Check signature length
         */
        if (PACKET_remaining(&signature) > (size_t)maxsig) {
            /* wrong packet length */
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                   SSL_R_WRONG_SIGNATURE_LENGTH);
            goto err;
        }

        md_ctx = EVP_MD_CTX_new();
        if (md_ctx == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                     ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /* FIXME: address RSA key... */
        EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (pctx == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                        ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (EVP_PKEY_CTX_set1_id(pctx, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LEN)
                != 1) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                        ERR_R_MALLOC_FAILURE);
            goto err;
        }

        EVP_MD_CTX_set_pkey_ctx(md_ctx, pctx);


        if (EVP_DigestVerifyInit(md_ctx, &pctx, md, NULL, pkey) <= 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                     ERR_R_EVP_LIB);
            goto err;
        }
        if (SSL_USE_PSS(s)) {
            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
                || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                                                RSA_PSS_SALTLEN_DIGEST) <= 0) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS, ERR_R_EVP_LIB);
                goto err;
            }
        }
        tbslen = construct_key_exchange_tbs_ntls(s, &tbs, PACKET_data(&params),
                                            PACKET_remaining(&params));
        if (tbslen == 0) {
            /* SSLfatal_ntls() already called */
            goto err;
        }

        rv = EVP_DigestVerify(md_ctx, PACKET_data(&signature),
                              PACKET_remaining(&signature), tbs, tbslen);
        OPENSSL_free(tbs);
        if (rv <= 0) {
            SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                     SSL_R_BAD_SIGNATURE);
            goto err;
        }
        EVP_MD_CTX_free(md_ctx);
        md_ctx = NULL;
        EVP_PKEY_CTX_free(pctx);
        pctx = NULL;
    } else {
        /* aNULL, aSRP or PSK do not need public keys */
        if (!(s->s3->tmp.new_cipher->algorithm_auth & (SSL_aNULL | SSL_aSRP))
            && !(alg_k & SSL_PSK)) {
            /* Might be wrong key type, check it */
            if (ssl3_check_cert_and_algorithm_ntls(s)) {
                SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                         SSL_R_BAD_DATA);
            }
            /* else this shouldn't happen, SSLfatal_ntls() already called */
            goto err;
        }
        /* still data left over */
        if (PACKET_remaining(pkt) != 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_KEY_EXCHANGE_NTLS,
                     SSL_R_EXTRA_DATA_IN_MESSAGE);
            goto err;
        }
    }

    return MSG_PROCESS_CONTINUE_READING;
 err:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    return MSG_PROCESS_ERROR;
}

MSG_PROCESS_RETURN tls_process_certificate_request_ntls(SSL *s, PACKET *pkt)
{
    size_t i;

    /* Clear certificate validity flags */
    for (i = 0; i < SSL_PKEY_NUM; i++)
        s->s3->tmp.valid_flags[i] = 0;

    {
        PACKET ctypes;

        /* get the certificate types */
        if (!PACKET_get_length_prefixed_1(pkt, &ctypes)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                     SSL_F_TLS_PROCESS_CERTIFICATE_REQUEST_NTLS,
                     SSL_R_LENGTH_MISMATCH);
            return MSG_PROCESS_ERROR;
        }

        if (!PACKET_memdup(&ctypes, &s->s3->tmp.ctype, &s->s3->tmp.ctype_len)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_PROCESS_CERTIFICATE_REQUEST_NTLS,
                     ERR_R_INTERNAL_ERROR);
            return MSG_PROCESS_ERROR;
        }

        if (SSL_USE_SIGALGS(s)) {
            PACKET sigalgs;

            if (!PACKET_get_length_prefixed_2(pkt, &sigalgs)) {
                SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                         SSL_F_TLS_PROCESS_CERTIFICATE_REQUEST_NTLS,
                         SSL_R_LENGTH_MISMATCH);
                return MSG_PROCESS_ERROR;
            }

            /*
             * Despite this being for certificates, preserve compatibility
             * with pre-TLS 1.3 and use the regular sigalgs field.
             */
            if (!tls1_save_sigalgs(s, &sigalgs, 0)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_PROCESS_CERTIFICATE_REQUEST_NTLS,
                         SSL_R_SIGNATURE_ALGORITHMS_ERROR);
                return MSG_PROCESS_ERROR;
            }
            if (!tls1_process_sigalgs(s)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_PROCESS_CERTIFICATE_REQUEST_NTLS,
                         ERR_R_MALLOC_FAILURE);
                return MSG_PROCESS_ERROR;
            }
        }

        /* get the CA RDNs */
        if (!parse_ca_names_ntls(s, pkt)) {
            /* SSLfatal_ntls() already called */
            return MSG_PROCESS_ERROR;
        }
    }

    if (PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                 SSL_F_TLS_PROCESS_CERTIFICATE_REQUEST_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        return MSG_PROCESS_ERROR;
    }

    /* we should setup a certificate to return.... */
    s->s3->tmp.cert_req = 1;

    return MSG_PROCESS_CONTINUE_PROCESSING;
}

MSG_PROCESS_RETURN tls_process_new_session_ticket_ntls(SSL *s, PACKET *pkt)
{
    unsigned int ticklen;
    unsigned long ticket_lifetime_hint, age_add = 0;
    unsigned int sess_len;
    RAW_EXTENSION *exts = NULL;
    PACKET nonce;

    PACKET_null_init(&nonce);

    if (!PACKET_get_net_4(pkt, &ticket_lifetime_hint)
        || !PACKET_get_net_2(pkt, &ticklen)
        || (PACKET_remaining(pkt) != ticklen)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_NEW_SESSION_TICKET_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    /*
     * Server is allowed to change its mind (in <=TLSv1.2) and send an empty
     * ticket. We already checked this TLSv1.3 case above, so it should never
     * be 0 here in that instance
     */
    if (ticklen == 0)
        return MSG_PROCESS_CONTINUE_READING;

    /*
     * Sessions must be immutable once they go into the session cache. Otherwise
     * we can get multi-thread problems. Therefore we don't "update" sessions,
     * we replace them with a duplicate. In TLSv1.3 we need to do this every
     * time a NewSessionTicket arrives because those messages arrive
     * post-handshake and the session may have already gone into the session
     * cache.
     */
    if (s->session->session_id_length > 0) {
        SSL_SESSION *new_sess;

        /*
         * We reused an existing session, so we need to replace it with a new
         * one
         */
        if ((new_sess = ssl_session_dup(s->session, 0)) == 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_PROCESS_NEW_SESSION_TICKET_NTLS,
                     ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if ((s->session_ctx->session_cache_mode & SSL_SESS_CACHE_CLIENT) != 0) {
            /*
             * In TLSv1.2 and below the arrival of a new tickets signals that
             * any old ticket we were using is now out of date, so we remove the
             * old session from the cache. We carry on if this fails
             */
            SSL_CTX_remove_session(s->session_ctx, s->session);
        }

        SSL_SESSION_free(s->session);
        s->session = new_sess;
    }

    /*
     * Technically the cast to long here is not guaranteed by the C standard -
     * but we use it elsewhere, so this should be ok.
     */
    s->session->time = (long)time(NULL);

    OPENSSL_free(s->session->ext.tick);
    s->session->ext.tick = NULL;
    s->session->ext.ticklen = 0;

    s->session->ext.tick = OPENSSL_malloc(ticklen);
    if (s->session->ext.tick == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_NEW_SESSION_TICKET_NTLS,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!PACKET_copy_bytes(pkt, s->session->ext.tick, ticklen)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_NEW_SESSION_TICKET_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    s->session->ext.tick_lifetime_hint = ticket_lifetime_hint;
    s->session->ext.tick_age_add = age_add;
    s->session->ext.ticklen = ticklen;

    /*
     * There are two ways to detect a resumed ticket session. One is to set
     * an appropriate session ID and then the server must return a match in
     * ServerHello. This allows the normal client session ID matching to work
     * and we know much earlier that the ticket has been accepted. The
     * other way is to set zero length session ID when the ticket is
     * presented and rely on the handshake to determine session resumption.
     * We choose the former approach because this fits in with assumptions
     * elsewhere in OpenSSL. The session ID is set to the SHA256 (or SHA1 is
     * SHA256 is disabled) hash of the ticket.
     */
    /*
     * TODO(size_t): we use sess_len here because EVP_Digest expects an int
     * but s->session->session_id_length is a size_t
     */
    if (!EVP_Digest(s->session->ext.tick, ticklen,
                    s->session->session_id, &sess_len,
                    EVP_sha256(), NULL)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_NEW_SESSION_TICKET_NTLS,
                 ERR_R_EVP_LIB);
        goto err;
    }
    s->session->session_id_length = sess_len;
    s->session->not_resumable = 0;

    return MSG_PROCESS_CONTINUE_READING;
 err:
    OPENSSL_free(exts);
    return MSG_PROCESS_ERROR;
}

/*
 * In TLSv1.3 this is called from the extensions code, otherwise it is used to
 * parse a separate message. Returns 1 on success or 0 on failure
 */
int tls_process_cert_status_body_ntls(SSL *s, PACKET *pkt)
{
    size_t resplen;
    unsigned int type;

    if (!PACKET_get_1(pkt, &type)
        || type != TLSEXT_STATUSTYPE_ocsp) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CERT_STATUS_BODY_NTLS,
                 SSL_R_UNSUPPORTED_STATUS_TYPE);
        return 0;
    }
    if (!PACKET_get_net_3_len(pkt, &resplen)
        || PACKET_remaining(pkt) != resplen) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CERT_STATUS_BODY_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }
    s->ext.ocsp.resp = OPENSSL_malloc(resplen);
    if (s->ext.ocsp.resp == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PROCESS_CERT_STATUS_BODY_NTLS,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!PACKET_copy_bytes(pkt, s->ext.ocsp.resp, resplen)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_CERT_STATUS_BODY_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }
    s->ext.ocsp.resp_len = resplen;

    return 1;
}


MSG_PROCESS_RETURN tls_process_cert_status_ntls(SSL *s, PACKET *pkt)
{
    if (!tls_process_cert_status_body_ntls(s, pkt)) {
        /* SSLfatal_ntls() already called */
        return MSG_PROCESS_ERROR;
    }

    return MSG_PROCESS_CONTINUE_READING;
}

/*
 * Perform miscellaneous checks and processing after we have received the
 * server's initial flight. In TLS1.3 this is after the Server Finished message.
 * In <=TLS1.2 this is after the ServerDone message. Returns 1 on success or 0
 * on failure.
 */
int tls_process_initial_server_flight_ntls(SSL *s)
{
    /*
     * at this point we check that we have the required stuff from
     * the server
     */
    if (!ssl3_check_cert_and_algorithm_ntls(s)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }

    /*
     * Call the ocsp status callback if needed. The |ext.ocsp.resp| and
     * |ext.ocsp.resp_len| values will be set if we actually received a status
     * message, or NULL and -1 otherwise
     */
    if (s->ext.status_type != TLSEXT_STATUSTYPE_nothing
            && s->ctx->ext.status_cb != NULL) {
        int ret = s->ctx->ext.status_cb(s, s->ctx->ext.status_arg);

        if (ret == 0) {
            SSLfatal_ntls(s, SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE,
                     SSL_F_TLS_PROCESS_INITIAL_SERVER_FLIGHT_NTLS,
                     SSL_R_INVALID_STATUS_RESPONSE);
            return 0;
        }
        if (ret < 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                     SSL_F_TLS_PROCESS_INITIAL_SERVER_FLIGHT_NTLS,
                     ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
# ifndef OPENSSL_NO_CT
    if (s->ct_validation_callback != NULL) {
        /* Note we validate the SCTs whether or not we abort on error */
        if (!ssl_validate_ct(s) && (s->verify_mode & SSL_VERIFY_PEER)) {
            /* SSLfatal_ntls() already called */
            return 0;
        }
    }
# endif

    return 1;
}

MSG_PROCESS_RETURN tls_process_server_done_ntls(SSL *s, PACKET *pkt)
{
    if (PACKET_remaining(pkt) > 0) {
        /* should contain no data */
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_SERVER_DONE_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        return MSG_PROCESS_ERROR;
    }

    if (!tls_process_initial_server_flight_ntls(s)) {
        /* SSLfatal_ntls() already called */
        return MSG_PROCESS_ERROR;
    }

    return MSG_PROCESS_FINISHED_READING;
}

static int tls_construct_cke_psk_preamble(SSL *s, WPACKET *pkt)
{
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_PSK_PREAMBLE,
             ERR_R_INTERNAL_ERROR);
    return 0;
}

static int tls_construct_cke_rsa(SSL *s, WPACKET *pkt)
{
# ifndef OPENSSL_NO_RSA
    unsigned char *encdata = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t enclen;
    unsigned char *pms = NULL;
    size_t pmslen = 0;

    if (s->session->peer == NULL) {
        /*
         * We should always have a server certificate with SSL_kRSA.
         */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_RSA,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pkey = X509_get0_pubkey(s->session->peer);
    if (EVP_PKEY_get0_RSA(pkey) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_RSA,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pmslen = SSL_MAX_MASTER_KEY_LENGTH;
    pms = OPENSSL_malloc(pmslen);
    if (pms == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_RSA,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }

    pms[0] = s->client_version >> 8;
    pms[1] = s->client_version & 0xff;
    /* TODO(size_t): Convert this function */
    if (RAND_bytes(pms + 2, (int)(pmslen - 2)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_RSA,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Fix buf for TLS and beyond */

    if (!WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_RSA,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL || EVP_PKEY_encrypt_init(pctx) <= 0
        || EVP_PKEY_encrypt(pctx, NULL, &enclen, pms, pmslen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_RSA,
                 ERR_R_EVP_LIB);
        goto err;
    }
    if (!WPACKET_allocate_bytes(pkt, enclen, &encdata)
            || EVP_PKEY_encrypt(pctx, encdata, &enclen, pms, pmslen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_RSA,
                 SSL_R_BAD_RSA_ENCRYPT);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    /* Fix buf for TLS and beyond */
    if (!WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_RSA,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Log the premaster secret, if logging is enabled. */
    if (!ssl_log_rsa_client_key_exchange(s, encdata, enclen, pms, pmslen)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    s->s3->tmp.pms = pms;
    s->s3->tmp.pmslen = pmslen;

    return 1;
 err:
    OPENSSL_clear_free(pms, pmslen);
    EVP_PKEY_CTX_free(pctx);

    return 0;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_RSA,
             ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int tls_construct_cke_dhe(SSL *s, WPACKET *pkt)
{
# ifndef OPENSSL_NO_DH
    DH *dh_clnt = NULL;
    const BIGNUM *pub_key;
    EVP_PKEY *ckey = NULL, *skey = NULL;
    unsigned char *keybytes = NULL;

    skey = s->s3->peer_tmp;
    if (skey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_DHE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ckey = ssl_generate_pkey(skey);
    if (ckey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_DHE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    dh_clnt = EVP_PKEY_get0_DH(ckey);

    if (dh_clnt == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_DHE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (ssl_derive(s, ckey, skey, 0) == 0) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    /* send off the data */
    DH_get0_key(dh_clnt, &pub_key, NULL);
    if (!WPACKET_sub_allocate_bytes_u16(pkt, BN_num_bytes(pub_key),
                                        &keybytes)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_DHE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    BN_bn2bin(pub_key, keybytes);
    EVP_PKEY_free(ckey);

    return 1;
 err:
    EVP_PKEY_free(ckey);
    return 0;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_DHE,
             ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int tls_construct_cke_ecdhe(SSL *s, WPACKET *pkt)
{
# ifndef OPENSSL_NO_EC
    unsigned char *encodedPoint = NULL;
    size_t encoded_pt_len = 0;
    EVP_PKEY *ckey = NULL, *skey = NULL;
    int ret = 0;

    skey = s->s3->peer_tmp;
    if (skey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_ECDHE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    ckey = ssl_generate_pkey(skey);
    if (ckey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_ECDHE,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (ssl_derive(s, ckey, skey, 0) == 0) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    /* Generate encoding of client key */
    encoded_pt_len = EVP_PKEY_get1_tls_encodedpoint(ckey, &encodedPoint);

    if (encoded_pt_len == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_ECDHE,
                 ERR_R_EC_LIB);
        goto err;
    }

    if (!WPACKET_sub_memcpy_u8(pkt, encodedPoint, encoded_pt_len)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_ECDHE,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ret = 1;
 err:
    OPENSSL_free(encodedPoint);
    EVP_PKEY_free(ckey);
    return ret;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_ECDHE,
             ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

static int tls_construct_cke_gost(SSL *s, WPACKET *pkt)
{
# ifndef OPENSSL_NO_GOST
    /* GOST key exchange message creation */
    EVP_PKEY_CTX *pkey_ctx = NULL;
    X509 *peer_cert;
    size_t msglen;
    unsigned int md_len;
    unsigned char shared_ukm[32], tmp[256];
    EVP_MD_CTX *ukm_hash = NULL;
    int dgst_nid = NID_id_GostR3411_94;
    unsigned char *pms = NULL;
    size_t pmslen = 0;

    if ((s->s3->tmp.new_cipher->algorithm_auth & SSL_aGOST12) != 0)
        dgst_nid = NID_id_GostR3411_2012_256;

    /*
     * Get server certificate PKEY and create ctx from it
     */
    peer_cert = s->session->peer;
    if (!peer_cert) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, SSL_F_TLS_CONSTRUCT_CKE_GOST,
               SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER);
        return 0;
    }

    pkey_ctx = EVP_PKEY_CTX_new(X509_get0_pubkey(peer_cert), NULL);
    if (pkey_ctx == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_GOST,
                 ERR_R_MALLOC_FAILURE);
        return 0;
    }
    /*
     * If we have send a certificate, and certificate key
     * parameters match those of server certificate, use
     * certificate key for key exchange
     */

    /* Otherwise, generate ephemeral key pair */
    pmslen = 32;
    pms = OPENSSL_malloc(pmslen);
    if (pms == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_GOST,
                 ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_encrypt_init(pkey_ctx) <= 0
        /* Generate session key
         * TODO(size_t): Convert this function
         */
        || RAND_bytes(pms, (int)pmslen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_GOST,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    };
    /*
     * Compute shared IV and store it in algorithm-specific context
     * data
     */
    ukm_hash = EVP_MD_CTX_new();
    if (ukm_hash == NULL
        || EVP_DigestInit(ukm_hash, EVP_get_digestbynid(dgst_nid)) <= 0
        || EVP_DigestUpdate(ukm_hash, s->s3->client_random,
                            SSL3_RANDOM_SIZE) <= 0
        || EVP_DigestUpdate(ukm_hash, s->s3->server_random,
                            SSL3_RANDOM_SIZE) <= 0
        || EVP_DigestFinal_ex(ukm_hash, shared_ukm, &md_len) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_GOST,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(ukm_hash);
    ukm_hash = NULL;
    if (EVP_PKEY_CTX_ctrl(pkey_ctx, -1, EVP_PKEY_OP_ENCRYPT,
                          EVP_PKEY_CTRL_SET_IV, 8, shared_ukm) < 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_GOST,
                 SSL_R_LIBRARY_BUG);
        goto err;
    }
    /* Make GOST keytransport blob message */
    /*
     * Encapsulate it into sequence
     */
    msglen = 255;
    if (EVP_PKEY_encrypt(pkey_ctx, tmp, &msglen, pms, pmslen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_GOST,
                 SSL_R_LIBRARY_BUG);
        goto err;
    }

    if (!WPACKET_put_bytes_u8(pkt, V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED)
            || (msglen >= 0x80 && !WPACKET_put_bytes_u8(pkt, 0x81))
            || !WPACKET_sub_memcpy_u8(pkt, tmp, msglen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_GOST,
                 ERR_R_INTERNAL_ERROR);
        goto err;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    s->s3->tmp.pms = pms;
    s->s3->tmp.pmslen = pmslen;

    return 1;
 err:
    EVP_PKEY_CTX_free(pkey_ctx);
    OPENSSL_clear_free(pms, pmslen);
    EVP_MD_CTX_free(ukm_hash);
    return 0;
# else
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_CKE_GOST,
             ERR_R_INTERNAL_ERROR);
    return 0;
# endif
}

int tls_construct_client_key_exchange_ntls(SSL *s, WPACKET *pkt)
{
    unsigned long alg_k;

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    /*
     * All of the construct functions below call SSLfatal_ntls() if necessary so
     * no need to do so here.
     */
    if ((alg_k & SSL_PSK)
        && !tls_construct_cke_psk_preamble(s, pkt))
        goto err;

    if (alg_k & (SSL_kRSA | SSL_kRSAPSK)) {
        if (!tls_construct_cke_rsa(s, pkt))
            goto err;
    } else if (alg_k & (SSL_kDHE | SSL_kDHEPSK)) {
        if (!tls_construct_cke_dhe(s, pkt))
            goto err;
    } else if (alg_k & (SSL_kECDHE | SSL_kECDHEPSK | SSL_kSM2DHE)) {
        if (!tls_construct_cke_ecdhe(s, pkt))
            goto err;
    } else if (alg_k & SSL_kGOST) {
        if (!tls_construct_cke_gost(s, pkt))
            goto err;
    } else if (!(alg_k & SSL_kPSK)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_CLIENT_KEY_EXCHANGE_NTLS, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    return 1;
 err:
    OPENSSL_clear_free(s->s3->tmp.pms, s->s3->tmp.pmslen);
    s->s3->tmp.pms = NULL;
    return 0;
}

int tls_client_key_exchange_post_work_ntls(SSL *s)
{
    unsigned char *pms = NULL;
    size_t pmslen = 0;

    pms = s->s3->tmp.pms;
    pmslen = s->s3->tmp.pmslen;

    if (pms == NULL && !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CLIENT_KEY_EXCHANGE_POST_WORK_NTLS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!ssl_generate_master_secret(s, pms, pmslen, 1)) {
        /* SSLfatal_ntls() already called */
        /* ssl_generate_master_secret frees the pms even on error */
        pms = NULL;
        pmslen = 0;
        goto err;
    }
    pms = NULL;
    pmslen = 0;

    return 1;
 err:
    OPENSSL_clear_free(pms, pmslen);
    s->s3->tmp.pms = NULL;
    return 0;
}

/*
 * Check a certificate can be used for client authentication. Currently check
 * cert exists, if we have a suitable digest for TLS 1.2 if static DH client
 * certificates can be used and optionally checks suitability for Suite B.
 */
static int ssl3_check_client_certificate_ntls(SSL *s)
{
    /* If no suitable signature algorithm can't use certificate */
    if (!tls_choose_sigalg_ntls(s, 0) || s->s3->tmp.sigalg == NULL)
        return 0;

    /*
     * If strict mode check suitability of chain before using it. This also
     * adjusts suite B digest if necessary.
     */
    if (s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT &&
        !tls1_check_chain(s, NULL, NULL, NULL, -2))
        return 0;
    return 1;
}

WORK_STATE tls_prepare_client_certificate_ntls(SSL *s, WORK_STATE wst)
{
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    int i;

    if (wst == WORK_MORE_A) {
        /* Let cert callback update client certificates if required */
        if (s->cert->cert_cb) {
            i = s->cert->cert_cb(s, s->cert->cert_cb_arg);
            if (i < 0) {
                s->rwstate = SSL_X509_LOOKUP;
                return WORK_MORE_A;
            }
            if (i == 0) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_TLS_PREPARE_CLIENT_CERTIFICATE_NTLS,
                         SSL_R_CALLBACK_FAILED);
                return WORK_ERROR;
            }
            s->rwstate = SSL_NOTHING;
        }
        if (ssl3_check_client_certificate_ntls(s)) {
            if (s->post_handshake_auth == SSL_PHA_REQUESTED) {
                return WORK_FINISHED_STOP;
            }
            return WORK_FINISHED_CONTINUE;
        }

        /* Fall through to WORK_MORE_B */
        wst = WORK_MORE_B;
    }

    /* We need to get a client cert */
    if (wst == WORK_MORE_B) {
        /*
         * If we get an error, we need to ssl->rwstate=SSL_X509_LOOKUP;
         * return(-1); We then get retied later
         */
        i = ssl_do_client_cert_cb_ntls(s, &x509, &pkey);
        if (i < 0) {
            s->rwstate = SSL_X509_LOOKUP;
            return WORK_MORE_B;
        }
        s->rwstate = SSL_NOTHING;
        if ((i == 1) && (pkey != NULL) && (x509 != NULL)) {
            if (!SSL_use_certificate(s, x509) || !SSL_use_PrivateKey(s, pkey))
                i = 0;
        } else if (i == 1) {
            i = 0;
            SSLerr(SSL_F_TLS_PREPARE_CLIENT_CERTIFICATE_NTLS,
                   SSL_R_BAD_DATA_RETURNED_BY_CALLBACK);
        }

        X509_free(x509);
        EVP_PKEY_free(pkey);
        if (i && !ssl3_check_client_certificate_ntls(s))
            i = 0;
        if (i == 0) {
            s->s3->tmp.cert_req = 2;
            if (!ssl3_digest_cached_records(s, 0)) {
                /* SSLfatal_ntls() already called */
                return WORK_ERROR;
            }
        }

        if (s->post_handshake_auth == SSL_PHA_REQUESTED)
            return WORK_FINISHED_STOP;
        return WORK_FINISHED_CONTINUE;
    }

    /* Shouldn't ever get here */
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_PREPARE_CLIENT_CERTIFICATE_NTLS,
             ERR_R_INTERNAL_ERROR);
    return WORK_ERROR;
}

int tls_construct_client_certificate_ntls(SSL *s, WPACKET *pkt)
{
    if (!ssl3_output_cert_chain_ntls(s, pkt,
            (s->s3->tmp.cert_req == 2) ? NULL : s->s3->tmp.sign_cert,
            (s->s3->tmp.cert_req == 2) ? NULL : s->s3->tmp.enc_cert)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }

    return 1;
}

int ssl3_check_cert_and_algorithm_ntls(SSL *s)
{
    const SSL_CERT_LOOKUP *clu;
    size_t idx;
    long alg_k, alg_a;

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    alg_a = s->s3->tmp.new_cipher->algorithm_auth;

    /* we don't have a certificate */
    if (!(alg_a & SSL_aCERT))
        return 1;

    /* This is the passed certificate */
    clu = ssl_cert_lookup_by_pkey(X509_get0_pubkey(s->session->peer), &idx);

    /* Check certificate is recognised and suitable for cipher */
    if (clu == NULL || (alg_a & clu->amask) == 0) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                 SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM_NTLS,
                 SSL_R_MISSING_SIGNING_CERT);
        return 0;
    }

# ifndef OPENSSL_NO_EC
    if (clu->amask & SSL_aECDSA) {
        if (ssl_check_srvr_ecc_cert_and_alg(s->session->peer, s))
            return 1;
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                 SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM_NTLS, SSL_R_BAD_ECC_CERT);
        return 0;
    }
# endif
# ifndef OPENSSL_NO_RSA
    if (alg_k & (SSL_kRSA | SSL_kRSAPSK) && idx != SSL_PKEY_RSA) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                 SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM_NTLS,
                 SSL_R_MISSING_RSA_ENCRYPTING_CERT);
        return 0;
    }
# endif
# ifndef OPENSSL_NO_DH
    if ((alg_k & SSL_kDHE) && (s->s3->peer_tmp == NULL)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
# endif

    return 1;
}

# ifndef OPENSSL_NO_NEXTPROTONEG
int tls_construct_next_proto_ntls(SSL *s, WPACKET *pkt)
{
    size_t len, padding_len;
    unsigned char *padding = NULL;

    len = s->ext.npn_len;
    padding_len = 32 - ((len + 2) % 32);

    if (!WPACKET_sub_memcpy_u8(pkt, s->ext.npn, len)
            || !WPACKET_sub_allocate_bytes_u8(pkt, padding_len, &padding)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLS_CONSTRUCT_NEXT_PROTO_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    memset(padding, 0, padding_len);

    return 1;
}
# endif

MSG_PROCESS_RETURN tls_process_hello_req_ntls(SSL *s, PACKET *pkt)
{
    if (PACKET_remaining(pkt) > 0) {
        /* should contain no data */
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_HELLO_REQ_NTLS,
                 SSL_R_LENGTH_MISMATCH);
        return MSG_PROCESS_ERROR;
    }

    if ((s->options & SSL_OP_NO_RENEGOTIATION)) {
        ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_NO_RENEGOTIATION);
        return MSG_PROCESS_FINISHED_READING;
    }

    /*
     * This is a historical discrepancy (not in the RFC) maintained for
     * compatibility reasons. If a TLS client receives a HelloRequest it will
     * attempt an abbreviated handshake.
     */
    SSL_renegotiate_abbreviated(s);

    return MSG_PROCESS_FINISHED_READING;
}

static MSG_PROCESS_RETURN tls_process_encrypted_extensions(SSL *s, PACKET *pkt)
{
    PACKET extensions;
    RAW_EXTENSION *rawexts = NULL;

    if (!PACKET_as_length_prefixed_2(pkt, &extensions)
            || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_TLS_PROCESS_ENCRYPTED_EXTENSIONS,
                 SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    if (!tls_collect_extensions_ntls(s, &extensions,
                                SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS, &rawexts,
                                NULL, 1)
            || !tls_parse_all_extensions_ntls(s, SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                                         rawexts, NULL, 0, 1)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    OPENSSL_free(rawexts);
    return MSG_PROCESS_CONTINUE_READING;

 err:
    OPENSSL_free(rawexts);
    return MSG_PROCESS_ERROR;
}

int ssl_do_client_cert_cb_ntls(SSL *s, X509 **px509, EVP_PKEY **ppkey)
{
    int i = 0;
# ifndef OPENSSL_NO_ENGINE
    if (s->ctx->client_cert_engine) {
        i = ENGINE_load_ssl_client_cert(s->ctx->client_cert_engine, s,
                                        SSL_get_client_CA_list(s),
                                        px509, ppkey, NULL, NULL, NULL);
        if (i != 0)
            return i;
    }
# endif
    if (s->ctx->client_cert_cb)
        i = s->ctx->client_cert_cb(s, px509, ppkey);
    return i;
}

int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk, WPACKET *pkt)
{
    int i;
    size_t totlen = 0, len, maxlen, maxverok = 0;
    int empty_reneg_info_scsv = !s->renegotiate;

    /* Set disabled masks for this session */
    if (!ssl_set_client_disabled(s)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CIPHER_LIST_TO_BYTES,
                 SSL_R_NO_PROTOCOLS_AVAILABLE);
        return 0;
    }

    if (sk == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CIPHER_LIST_TO_BYTES,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

# ifdef OPENSSL_MAX_TLS1_2_CIPHER_LENGTH
#  if OPENSSL_MAX_TLS1_2_CIPHER_LENGTH < 6
#   error Max cipher length too short
#  endif
    /*
     * Some servers hang if client hello > 256 bytes as hack workaround
     * chop number of supported ciphers to keep it well below this if we
     * use TLS v1.2
     */
    if (TLS1_get_version(s) >= TLS1_2_VERSION)
        maxlen = OPENSSL_MAX_TLS1_2_CIPHER_LENGTH & ~1;
    else
# endif
        /* Maximum length that can be stored in 2 bytes. Length must be even */
        maxlen = 0xfffe;

    if (empty_reneg_info_scsv)
        maxlen -= 2;
    if (s->mode & SSL_MODE_SEND_FALLBACK_SCSV)
        maxlen -= 2;

    for (i = 0; i < sk_SSL_CIPHER_num(sk) && totlen < maxlen; i++) {
        const SSL_CIPHER *c;

        c = sk_SSL_CIPHER_value(sk, i);
        /* Skip disabled ciphers */
        if (ssl_cipher_disabled(s, c, SSL_SECOP_CIPHER_SUPPORTED, 0))
            continue;

        if (!s->method->put_cipher_by_char(c, pkt, &len)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CIPHER_LIST_TO_BYTES,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /* Sanity check that the maximum version we offer has ciphers enabled */
        if (!maxverok) {
            if (c->max_tls >= s->s3->tmp.max_ver
                    && c->min_tls <= s->s3->tmp.max_ver)
                maxverok = 1;

        }

        totlen += len;
    }

    if (totlen == 0 || !maxverok) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CIPHER_LIST_TO_BYTES,
                 SSL_R_NO_CIPHERS_AVAILABLE);

        if (!maxverok)
            ERR_add_error_data(1, "No ciphers enabled for max supported "
                                  "SSL/TLS version");

        return 0;
    }

    if (totlen != 0) {
        if (empty_reneg_info_scsv) {
            static SSL_CIPHER scsv = {
                0, NULL, NULL, SSL3_CK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            if (!s->method->put_cipher_by_char(&scsv, pkt, &len)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_SSL_CIPHER_LIST_TO_BYTES, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
        if (s->mode & SSL_MODE_SEND_FALLBACK_SCSV) {
            static SSL_CIPHER scsv = {
                0, NULL, NULL, SSL3_CK_FALLBACK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            if (!s->method->put_cipher_by_char(&scsv, pkt, &len)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                         SSL_F_SSL_CIPHER_LIST_TO_BYTES, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    }

    return 1;
}

int tls_construct_end_of_early_data_ntls(SSL *s, WPACKET *pkt)
{
    if (s->early_data_state != SSL_EARLY_DATA_WRITE_RETRY
            && s->early_data_state != SSL_EARLY_DATA_FINISHED_WRITING) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_END_OF_EARLY_DATA_NTLS,
                 ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    s->early_data_state = SSL_EARLY_DATA_FINISHED_WRITING;
    return 1;
}

#endif

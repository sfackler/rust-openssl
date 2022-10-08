#include <stdio.h>
#include <string.h>
#include "apps.h"
#include "progs.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "../ssl/ssl_local.h"

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_IN, OPT_OUT,
    OPT_NEW, OPT_DC_KEY,
    OPT_EE_CERT, OPT_EE_KEY,
    OPT_SEC, OPT_MD,
    OPT_EXPECT_VERIFY_MD, OPT_CLIENT, OPT_SERVER,
    OPT_TEXT, OPT_NOOUT
} OPTION_CHOICE;

const OPTIONS delecred_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"in", OPT_IN, '<', "input file"},
    {"out", OPT_OUT, '>', "output file"},
    {"new", OPT_NEW, '-', "generate a new delegated credential"},
    {"dc_key", OPT_DC_KEY, 's', "private key of delegated credential"},
    {"parent_cert", OPT_EE_CERT, 's', "end-entity certificate used to sign the dc"},
    {"parent_key", OPT_EE_KEY, 's', "private key of the end-entity certificate"},
    {"sec", OPT_SEC, 'p', "dc valid time, default is 604800 seconds(7 days)"},
    {"expect_verify_md", OPT_EXPECT_VERIFY_MD, 's', "expected message digest of signature algorithm of dc key pair"},
    {"", OPT_MD, '-', "Any supported digest"},
    {"client", OPT_CLIENT, '-', "client DC"},
    {"server", OPT_SERVER, '-', "server DC"},
    {"text", OPT_TEXT, '-', "print the dc in text form"},
    {"noout", OPT_NOOUT, '-', "no dc output"},
    {NULL}
};

int delecred_main(int argc, char **argv)
{
    int ret = 1;
    int res;
    char *prog;
    size_t i;
    OPTION_CHOICE o;
    char *infile = NULL, *outfile = NULL;
    BIO *in = NULL, *out = NULL;
    int text = 0;
    int noout = 0;
    int new_flag = 0;
    char *dc_key = NULL;
    char *ee_cert_file = NULL, *ee_key_file = NULL;
    char *expect_verify_hash = NULL;
    const EVP_MD *expect_verify_md = EVP_md_null();
    const EVP_MD *sign_md = EVP_md_null();
    int is_server = 1;
    int valid_time = 7 * 24 * 3600;
    DELEGATED_CREDENTIAL *dc = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *dc_pkey = NULL;
    X509 *ee_cert = NULL;
    EVP_PKEY *ee_pkey = NULL;
    unsigned char *dc_raw = NULL;
    unsigned long dc_raw_len = 0;

    prog = opt_init(argc, argv, delecred_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
            case OPT_EOF:
            case OPT_ERR:
opthelp:
                BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
                goto end;
            case OPT_HELP:
                opt_help(delecred_options);
                ret = 0;
                goto end;
            case OPT_IN:
                infile = opt_arg();
                break;
            case OPT_OUT:
                outfile = opt_arg();
                break;
            case OPT_NEW:
                new_flag = 1;
                break;
            case OPT_DC_KEY:
                dc_key = opt_arg();
                break;
            case OPT_EE_CERT:
                ee_cert_file = opt_arg();
                break;
            case OPT_EE_KEY:
                ee_key_file = opt_arg();
                break;
            case OPT_SEC:
                opt_int(opt_arg(), &valid_time);
                break;
            case OPT_EXPECT_VERIFY_MD:
                expect_verify_hash = opt_arg();
                if (!opt_md(expect_verify_hash, &expect_verify_md))
                    goto opthelp;
                break;
            case OPT_MD:
                if (!opt_md(opt_unknown(), &sign_md))
                    goto opthelp;
                break;
            case OPT_CLIENT:
                is_server = 0;
                break;
            case OPT_SERVER:
                is_server = 1;
                break;
            case OPT_TEXT:
                text = 1;
                break;
            case OPT_NOOUT:
                noout = 1;
                break;
        }
    }

    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (infile) {
        dc = DC_load_from_file(infile);

        if (dc == NULL) {
            goto end;
        }

        if (text) {
            if (!DC_print(bio_out, dc))
                goto end;
        }
    } else if (new_flag) {
        dc_pkey = load_key(dc_key, FORMAT_PEM, 1, NULL, e, "key");
        if (dc_pkey == NULL) {
            goto end;
        }

        ee_cert = load_cert(ee_cert_file, FORMAT_PEM, "end-entity cert");
        if (ee_cert == NULL) {
            goto end;
        }

        ee_pkey = load_key(ee_key_file, FORMAT_PEM, 1, NULL, e, "end-entity key");
        if (ee_pkey == NULL) {
            goto end;
        }

        dc = DC_new();
        if (dc == NULL) {
            BIO_printf(bio_err, "failed to new DC\n");
            goto end;
        }

        if (!DC_sign(dc, dc_pkey, valid_time, EVP_MD_type(expect_verify_md),
                     ee_cert, ee_pkey, sign_md, is_server)) {
            BIO_printf(bio_err, "failed to sign DC\n");
            goto end;
        }
    } else {
        goto opthelp;
    }

    if (!noout) {
        dc_raw = DC_get0_raw_byte(dc);
        dc_raw_len = DC_get_raw_byte_len(dc);

        if (dc_raw == NULL || dc_raw_len <= 0) {
            BIO_printf(bio_err, "Invalid DC raw\n");
            goto end;
        }

        if (outfile) {
            out = BIO_new_file(outfile, "w");
            if (out == NULL)
                goto end;
        } else {
            out = dup_bio_out(FORMAT_TEXT);
        }

        for (i = 0; i < dc_raw_len; i++) {
            res = BIO_printf(out, "%02x", dc_raw[i]);
            if (res <= 0) {
                BIO_printf(bio_out, "output dc error");
                goto end;
            }
        }
    }

    ret = 0;

end:
    if (ret != 0)
        ERR_print_errors(bio_err);

    release_engine(e);
    EVP_PKEY_free(ee_pkey);
    X509_free(ee_cert);
    EVP_PKEY_free(dc_pkey);
    DC_free(dc);
    BIO_free(out);
    BIO_free(in);

    return ret;
}


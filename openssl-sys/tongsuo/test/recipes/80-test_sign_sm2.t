use strict;
use warnings;

use POSIX;
use File::Path 2.00 qw/rmtree/;
use OpenSSL::Test qw/:DEFAULT data_file merge_files/;
use OpenSSL::Test::Utils;
use File::Spec::Functions qw/catfile catdir/;

my $test_name = "test_sign_sm2";
setup($test_name);

plan skip_all => "sm2 is not supported by this OpenSSL build"
    if disabled("sm2") || disabled("sm3");

plan tests => 20;

my $CADIR = catdir(".", "ca");
my $SUBCADIR = catdir(".", "subca");

rmtree(${test_name}, { safe => 0 });
rmtree(${CADIR}, { safe => 0 });
rmtree(${SUBCADIR}, { safe => 0 });

sub setup_ca {
    my $CATOP = shift;

    mkdir($CATOP);
    mkdir(catdir($CATOP, "newcerts"));
    mkdir(catdir($CATOP, "db"));
    mkdir(catdir($CATOP, "private"));
    mkdir(catdir($CATOP, "crl"));

    open OUT, ">", catfile($CATOP, "db", "index");
    close OUT;
    open OUT, ">", catfile($CATOP, "db", "serial");
    print OUT "00\n";
    close OUT;
}

mkdir($test_name);
setup_ca(${CADIR});
setup_ca(${SUBCADIR});

# sm2 ca
ok(run(app(["openssl", "ecparam",
    "-genkey", "-name", "SM2",
    "-out", catfile(".", $test_name, "ca.key")])));

ok(run(app(["openssl", "req",
    "-config", data_file("ca.cnf"),
    "-new", "-key", catfile(".", $test_name, "ca.key"),
    "-out", catfile(".", $test_name, "ca.csr"),
    "-sm3", "-nodes", "-sigopt", "sm2_id:1234567812345678",
    "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=root ca"])));

ok(run(app(["openssl", "ca",
    "-selfsign", "-config", data_file("ca.cnf"),
    "-in", catfile(".", $test_name, "ca.csr"),
    "-keyfile", catfile(".", $test_name, "ca.key"),
    "-extensions", "v3_ca",
    "-days", "365",
    "-notext", "-out", catfile(".", $test_name, "ca.crt"),
    "-md", "sm3",
    "-batch"])));

# sm2 subca
ok(run(app(["openssl", "ecparam",
    "-genkey", "-name", "SM2",
    "-out", catfile(".", $test_name, "subca.key")])));

ok(run(app(["openssl", "req",
    "-config", data_file("ca.cnf"),
    "-new", "-key", catfile(".", $test_name, "subca.key"),
    "-out", catfile(".", $test_name, "subca.csr"),
    "-sm3", "-nodes", "-sigopt", "sm2_id:1234567812345678",
    "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=sub ca"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("ca.cnf"),
    "-in", catfile(".", $test_name, "subca.csr"),
    "-cert", catfile(".", $test_name, "ca.crt"),
    "-keyfile", catfile(".", $test_name, "ca.key"),
    "-extensions", "v3_intermediate_ca",
    "-days", "365",
    "-notext", "-out", catfile(".", $test_name, "subca.crt"),
    "-md", "sm3",
    "-batch"])));

# cat ca.crt subca.crt > chain-ca.crt
merge_files(catfile(".", $test_name, "ca.crt"),
    catfile(".", $test_name, "subca.crt"),
    catfile(".", $test_name, "chain-ca.crt"));

# server sm2 double certs
ok(run(app(["openssl", "ecparam",
    "-name", "SM2",
    "-out", catfile(".", $test_name, "server_sm2.param")])));

ok(run(app(["openssl", "req",
    "-config", data_file("subca.cnf"),
    "-newkey", "ec:" . catfile(".", $test_name, "server_sm2.param"),
    "-nodes", "-keyout", catfile(".", $test_name, "server_sign.key"),
    "-sm3", "-sigopt", "sm2_id:1234567812345678",
    "-new", "-out", catfile(".", $test_name, "server_sign.csr"),
    "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=server sign"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-extensions", "sign_req",
    "-days", "365",
    "-in", catfile(".", $test_name, "server_sign.csr"),
    "-notext", "-out", catfile(".", $test_name, "server_sign.crt"),
    "-cert", catfile(".", $test_name, "subca.crt"),
    "-keyfile", catfile(".", $test_name, "subca.key"),
    "-md", "sm3",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-extensions", "sign_req",
    "-startdate", "20000101000000Z",
    "-enddate", "20010101000000Z",
    "-in", catfile(".", $test_name, "server_sign.csr"),
    "-notext", "-out", catfile(".", $test_name, "server_sign_expire.crt"),
    "-cert", catfile(".", $test_name, "subca.crt"),
    "-keyfile", catfile(".", $test_name, "subca.key"),
    "-md", "sm3",
    "-batch"])));

ok(run(app(["openssl", "req",
    "-config", data_file("subca.cnf"),
    "-newkey", "ec:" . catfile(".", $test_name, "server_sm2.param"),
    "-nodes", "-keyout", catfile(".", $test_name, "server_enc.key"),
    "-sm3", "-sigopt", "sm2_id:1234567812345678",
    "-new", "-out", catfile(".", $test_name, "server_enc.csr"),
    "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=server enc"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-extensions", "enc_req",
    "-days", "365",
    "-in", catfile(".", $test_name, "server_enc.csr"),
    "-notext", "-out", catfile(".", $test_name, "server_enc.crt"),
    "-cert", catfile(".", $test_name, "subca.crt"),
    "-keyfile", catfile(".", $test_name, "subca.key"),
    "-md", "sm3",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-extensions", "enc_req",
    "-startdate", "20000101000000Z",
    "-enddate", "20010101000000Z",
    "-in", catfile(".", $test_name, "server_enc.csr"),
    "-notext", "-out", catfile(".", $test_name, "server_enc_expire.crt"),
    "-cert", catfile(".", $test_name, "subca.crt"),
    "-keyfile", catfile(".", $test_name, "subca.key"),
    "-md", "sm3",
    "-batch"])));

# client sm2 double certs
ok(run(app(["openssl", "ecparam",
    "-name", "SM2",
    "-out", catfile(".", $test_name, "client_sm2.param")])));

ok(run(app(["openssl", "req",
    "-config", data_file("subca.cnf"),
    "-newkey", "ec:" . catfile(".", $test_name, "client_sm2.param"),
    "-nodes", "-keyout", catfile(".", $test_name, "client_sign.key"),
    "-sm3", "-sigopt", "sm2_id:1234567812345678",
    "-new", "-out", catfile(".", $test_name, "client_sign.csr"),
    "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=client sign"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-extensions", "sign_req",
    "-days", "365",
    "-in", catfile(".", $test_name, "client_sign.csr"),
    "-notext", "-out", catfile(".", $test_name, "client_sign.crt"),
    "-cert", catfile(".", $test_name, "subca.crt"),
    "-keyfile", catfile(".", $test_name, "subca.key"),
    "-md", "sm3",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-extensions", "sign_req",
    "-startdate", "20000101000000Z",
    "-enddate", "20010101000000Z",
    "-in", catfile(".", $test_name, "client_sign.csr"),
    "-notext", "-out", catfile(".", $test_name, "client_sign_expire.crt"),
    "-cert", catfile(".", $test_name, "subca.crt"),
    "-keyfile", catfile(".", $test_name, "subca.key"),
    "-md", "sm3",
    "-batch"])));

ok(run(app(["openssl", "req",
    "-config", data_file("subca.cnf"),
    "-newkey", "ec:" . catfile(".", $test_name, "client_sm2.param"),
    "-nodes", "-keyout", catfile(".", $test_name, "client_enc.key"),
    "-sm3", "-sigopt", "sm2_id:1234567812345678",
    "-new", "-out", catfile(".", $test_name, "client_enc.csr"),
    "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=client enc"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-extensions", "enc_req",
    "-days", "365",
    "-in", catfile(".", $test_name, "client_enc.csr"),
    "-notext", "-out", catfile(".", $test_name, "client_enc.crt"),
    "-cert", catfile(".", $test_name, "subca.crt"),
    "-keyfile", catfile(".", $test_name, "subca.key"),
    "-md", "sm3",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-extensions", "enc_req",
    "-startdate", "20000101000000Z",
    "-enddate", "20010101000000Z",
    "-in", catfile(".", $test_name, "client_enc.csr"),
    "-notext", "-out", catfile(".", $test_name, "client_enc_expire.crt"),
    "-cert", catfile(".", $test_name, "subca.crt"),
    "-keyfile", catfile(".", $test_name, "subca.key"),
    "-md", "sm3",
    "-batch"])));

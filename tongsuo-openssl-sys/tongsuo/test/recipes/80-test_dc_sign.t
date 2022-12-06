use strict;
use warnings;

use File::Path 2.00 qw/rmtree/;
use OpenSSL::Test qw/:DEFAULT data_file/;
use OpenSSL::Test::Utils;
use File::Spec::Functions qw/catfile catdir/;

setup("test_dc_sign");

plan skip_all => "dc_sign is not supported by this OpenSSL build"
    if disabled("delegated-credential");

plan skip_all => "sign dc use ecc certs but no-ec"
    if disabled("ec");

plan tests => 22;

my $DCDIR = catdir(".", "dc");
my $CADIR = catdir(".", "ca");
my $SUBCADIR = catdir(".", "subca");

rmtree(${DCDIR}, { safe => 0 });
rmtree(${CADIR}, { safe => 0 });
rmtree(${SUBCADIR}, { safe => 0 });

sub setup_ca {
    my $CATOP = shift;

    mkdir($CATOP);
    mkdir(catdir($CATOP, "newcerts"));
    mkdir(catdir($CATOP, "db"));
    mkdir(catdir($CATOP, "private"));
    mkdir(catdir($CATOP, "crl"));

    open OUT, ">", catfile($CATOP, "db", "index.txt");
    close OUT;
    open OUT, ">", catfile($CATOP, "db", "serial");
    print OUT "00\n";
    close OUT;
}

mkdir($DCDIR);
setup_ca(${CADIR});
setup_ca(${SUBCADIR});

# ca
ok(run(app(["openssl", "genpkey",
    "-algorithm", "ec",
     "-pkeyopt", "ec_paramgen_curve:P-256",
     "-out", catfile(".", "dc", "dc-ecc-root.key")])));

ok(run(app(["openssl", "req",
    "-config", data_file("ca.cnf"),
    "-new", "-key", catfile(".", "dc", "dc-ecc-root.key"),
    "-out", catfile(".", "dc", "dc-ecc-root.csr"),
    "-sha256", "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=root ca",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-selfsign", "-config", data_file("ca.cnf"),
    "-keyfile", catfile(".", "dc", "dc-ecc-root.key"),
    "-in", catfile(".", "dc", "dc-ecc-root.csr"),
    "-extensions", "v3_ca",
    "-days", "3650",
    "-out", catfile(".", "dc", "dc-ecc-root.crt"),
    "-md", "sha256",
    "-batch"])));

# sub ca
ok(run(app(["openssl", "genpkey",
    "-algorithm", "ec",
     "-pkeyopt", "ec_paramgen_curve:P-256",
     "-out", catfile(".", "dc", "dc-ecc-subca.key")])));

ok(run(app(["openssl", "req",
    "-config", data_file("ca.cnf"),
    "-new", "-key", catfile(".", "dc", "dc-ecc-subca.key"),
    "-out", catfile(".", "dc", "dc-ecc-subca.csr"),
    "-sha256", "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=sub ca",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("ca.cnf"),
    "-cert", catfile(".", "dc", "dc-ecc-root.crt"),
    "-keyfile", catfile(".", "dc", "dc-ecc-root.key"),
    "-in", catfile(".", "dc", "dc-ecc-subca.csr"),
    "-extensions", "v3_intermediate_ca",
    "-days", "3650",
    "-out", catfile(".", "dc", "dc-ecc-subca.crt"),
    "-md", "sha256",
    "-batch"])));

my $dc_ecc_root_path = catfile(".", "dc", "dc-ecc-root.crt");
my $dc_ecc_subca_path = catfile(".", "dc", "dc-ecc-subca.crt");
my $dc_ecc_chain_ca_path = catfile(".", "dc", "dc-ecc-chain-ca.crt");

open my $dc_ecc_chain_ca, '>', $dc_ecc_chain_ca_path
    or die "Trying to write to $dc_ecc_chain_ca_path: $!\n";
open my $dc_ecc_root, "<", $dc_ecc_root_path
    or die "Could not open $dc_ecc_root_path: $!\n";
open my $dc_ecc_subca, "<", $dc_ecc_subca_path
    or die "Could not open $dc_ecc_subca_path: $!\n";

while (my $line = <$dc_ecc_root>) {
    print $dc_ecc_chain_ca $line;
}

while (my $line = <$dc_ecc_subca>) {
    print $dc_ecc_chain_ca $line;
}

close $dc_ecc_root;
close $dc_ecc_subca;
close $dc_ecc_chain_ca;

# server
ok(run(app(["openssl", "genpkey",
    "-algorithm", "ec",
     "-pkeyopt", "ec_paramgen_curve:P-256",
     "-out", catfile(".", "dc", "dc-ecc-leaf.key")])));

ok(run(app(["openssl", "req",
    "-config", data_file("subca.cnf"),
    "-new", "-key", catfile(".", "dc", "dc-ecc-leaf.key"),
    "-out", catfile(".", "dc", "dc-ecc-leaf.csr"),
    "-sha256", "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=server",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-cert", catfile(".", "dc", "dc-ecc-subca.crt"),
    "-keyfile", catfile(".", "dc", "dc-ecc-subca.key"),
    "-in", catfile(".", "dc", "dc-ecc-leaf.csr"),
    "-extensions", "server_cert",
    "-days", "3650",
    "-out", catfile(".", "dc", "dc-ecc-leaf.crt"),
    "-md", "sha256",
    "-batch"])));

# client
ok(run(app(["openssl", "genpkey",
    "-algorithm", "ec",
     "-pkeyopt", "ec_paramgen_curve:P-256",
     "-out", catfile(".", "dc", "dc-ecc-leaf-clientUse.key")])));

ok(run(app(["openssl", "req",
    "-config", data_file("subca.cnf"),
    "-new", "-key", catfile(".", "dc", "dc-ecc-leaf-clientUse.key"),
    "-out", catfile(".", "dc", "dc-ecc-leaf-clientUse.csr"),
    "-sha256", "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=client",
    "-batch"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-cert", catfile(".", "dc", "dc-ecc-subca.crt"),
    "-keyfile", catfile(".", "dc", "dc-ecc-subca.key"),
    "-in", catfile(".", "dc", "dc-ecc-leaf-clientUse.csr"),
    "-extensions", "usr_cert",
    "-days", "3650",
    "-out", catfile(".", "dc", "dc-ecc-leaf-clientUse.crt"),
    "-md", "sha256",
    "-batch"])));

# server dc
ok(run(app(["openssl", "genpkey",
    "-algorithm", "ec",
     "-pkeyopt", "ec_paramgen_curve:P-256",
     "-out", catfile(".", "dc", "dc-ecc-server.key")])));

ok(run(app(["openssl", "delecred",
    "-new", "-server",
    "-sec", "604800",
    "-dc_key", catfile(".", "dc", "dc-ecc-server.key"),
    "-out", catfile(".", "dc", "dc-ecc-server.dc"),
    "-parent_cert", catfile(".", "dc", "dc-ecc-leaf.crt"),
    "-parent_key", catfile(".", "dc", "dc-ecc-leaf.key"),
    "-expect_verify_md", "sha256",
    "-sha256"])));

ok(run(app(["openssl", "delecred",
    "-in", catfile(".", "dc", "dc-ecc-server.dc"),
    "-text", "-noout"])));

# client dc
ok(run(app(["openssl", "genpkey",
    "-algorithm", "ec",
     "-pkeyopt", "ec_paramgen_curve:P-256",
     "-out", catfile(".", "dc", "dc-ecc-client.key")])));

ok(run(app(["openssl", "delecred",
    "-new", "-client",
    "-sec", "604800",
    "-dc_key", catfile(".", "dc", "dc-ecc-client.key"),
    "-out", catfile(".", "dc", "dc-ecc-client.dc"),
    "-parent_cert", catfile(".", "dc", "dc-ecc-leaf-clientUse.crt"),
    "-parent_key", catfile(".", "dc", "dc-ecc-leaf-clientUse.key"),
    "-expect_verify_md", "sha256",
    "-sha256"])));

ok(run(app(["openssl", "delecred",
    "-in", catfile(".", "dc", "dc-ecc-client.dc"),
    "-text", "-noout"])));

# server expire dc
ok(run(app(["openssl", "genpkey",
    "-algorithm", "ec",
     "-pkeyopt", "ec_paramgen_curve:P-256",
     "-out", catfile(".", "dc", "dc-ecc-server-expire.key")])));

ok(run(app(["openssl", "delecred",
    "-new", "-server",
    "-sec", "1",
    "-dc_key", catfile(".", "dc", "dc-ecc-server-expire.key"),
    "-out", catfile(".", "dc", "dc-ecc-server-expire.dc"),
    "-parent_cert", catfile(".", "dc", "dc-ecc-leaf.crt"),
    "-parent_key", catfile(".", "dc", "dc-ecc-leaf.key"),
    "-expect_verify_md", "sha256",
    "-sha256"])));

# client expire dc
ok(run(app(["openssl", "genpkey",
    "-algorithm", "ec",
     "-pkeyopt", "ec_paramgen_curve:P-256",
     "-out", catfile(".", "dc", "dc-ecc-client-expire.key")])));

ok(run(app(["openssl", "delecred",
    "-new", "-client",
    "-sec", "1",
    "-dc_key", catfile(".", "dc", "dc-ecc-client-expire.key"),
    "-out", catfile(".", "dc", "dc-ecc-client-expire.dc"),
    "-parent_cert", catfile(".", "dc", "dc-ecc-leaf-clientUse.crt"),
    "-parent_key", catfile(".", "dc", "dc-ecc-leaf-clientUse.key"),
    "-expect_verify_md", "sha256",
    "-sha256"])));

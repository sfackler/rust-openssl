#! /usr/bin/env perl

use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file srctop_dir/;
use File::Temp qw(tempfile);

setup("test_babasslapi");

plan skip_all => "No TLS/SSL protocols are supported by this OpenSSL build"
    if alldisabled(grep { $_ ne "ssl3" } available_protocols("tls"));

plan tests => 1;

(undef, my $tmpfilename) = tempfile();

ok(run(test(["babasslapitest", srctop_dir("test", "certs"),
             srctop_file("test", "recipes", "90-test_sslapi_data",
                         "passwd.txt"), $tmpfilename])),
             "running babasslapitest");

unlink $tmpfilename;

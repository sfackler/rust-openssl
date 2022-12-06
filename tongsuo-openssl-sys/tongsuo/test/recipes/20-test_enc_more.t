#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use File::Spec::Functions qw/catfile/;
use File::Copy;
use File::Compare qw/compare_text/;
use File::Basename;
use OpenSSL::Test qw/:DEFAULT srctop_file data_file/;

setup("test_enc_more");

my $testsrc = srctop_file("test", "recipes", basename($0));

my $plaintext = catfile(".", "testdatafile");
my $test_plain = data_file("plain_for_wrap.txt");
my $wrap_plaintext = catfile(".", "plain_for_wrap");
my $fail = "";
my $cmd = "openssl";

my $ciphersstatus = undef;
my @ciphers =
    grep(! /^$|^[^-]/,
        (map { split /\s+/ }
          run(app([$cmd, "enc", "-ciphers"]),
              capture => 1, statusvar => \$ciphersstatus)));

plan tests => 3 + scalar @ciphers;

SKIP: {
    skip "Problems getting ciphers...", 1 + scalar(@ciphers)
        unless ok($ciphersstatus, "Running 'openssl enc -ciphers'");
    unless (ok(copy($testsrc, $plaintext), "Copying $testsrc to $plaintext")
        && ok(copy($test_plain, $wrap_plaintext),
              "Copying $test_plain to $wrap_plaintext")) {
        diag($!);
        skip "Not initialized, skipping...", scalar(@ciphers);
    }

    foreach my $cipher (@ciphers) {
        my $plain;
        if ($cipher =~ /wrap|^$|^[^-]/) {
            $plain = $wrap_plaintext;
        } else {
            $plain = $plaintext;
        }
        my $ciphername = substr $cipher, 1;
        my $cipherfile = "$plain.$ciphername.cipher";
        my $clearfile = "$plain.$ciphername.clear";
        my @common = ( $cmd, "enc", "$cipher", "-k", "test" );

        ok(run(app([@common, "-e", "-in", $plain, "-out", $cipherfile]))
           && compare_text($plain, $cipherfile) != 0
           && run(app([@common, "-d", "-in", $cipherfile, "-out", $clearfile]))
           && compare_text($plain, $clearfile) == 0
           , $ciphername);
        unlink $cipherfile, $clearfile;
    }
}

unlink $plaintext;
unlink $wrap_plaintext;

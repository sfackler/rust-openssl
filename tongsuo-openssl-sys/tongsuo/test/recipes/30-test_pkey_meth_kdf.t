#! /usr/bin/env perl
# Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use OpenSSL::Test::Simple;
use strict;
use warnings;

use File::Spec::Functions qw/canonpath/;
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_pkey_meth_kdf");

plan skip_all => "asan ci seem has problem of this case"
    if !disabled("asan");

simple_test("test_pkey_meth_kdf", "pkey_meth_kdf_test");


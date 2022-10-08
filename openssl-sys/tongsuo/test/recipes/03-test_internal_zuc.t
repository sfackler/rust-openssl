#! /usr/bin/env perl
# Copyright 2021 Ant Group. All Rights Reserved.
# Copyright 2018 BaishanCloud. All Rights Reserved.

use strict;
use OpenSSL::Test;              # get 'plan'
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_internal_zuc");

plan skip_all => "This test is unsupported in a shared library build on Windows"
    if $^O eq 'MSWin32' && !disabled("shared");

simple_test("test_internal_zuc", "zuc_internal_test", "zuc");

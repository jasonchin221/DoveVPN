#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Std;
use File::Find;
use Cwd;

use vars qw($opt_h $opt_d);
getopts('hd');

my @test_files;
my $test_mod;
my $test_dir = 'test';
#my $std_out_file = "test.log";
my $curr_dir = getcwd();
my $test_cmd = $curr_dir."/"."$test_dir/ssl_test";
my $ser_ca = $curr_dir."/"."$test_dir/pem/ser_cacert.pem";
my $ser_key = $curr_dir."/"."$test_dir/pem/ser_privkey.pem";
my $cli_ca = $curr_dir."/"."$test_dir/pem/cli_cacert.pem";
my $cli_key = $curr_dir."/"."$test_dir/pem/cli_privkey.pem";
my $ca = "$ser_ca,$cli_ca";
my $key = "$ser_key,$cli_key";
my $port = 446;
my $cmd_param = "cmd_param";
my $test_info = "test_info";
my $cmd_str;

my @testcase = (
    {
        $cmd_param => "-c $ca -k $key -p $port",
        $test_info => "DoveSSL--->DoveSSL",
    },
#    {
#        $cmd_param => "-c $ca -k $key -p $port -C",
#        $test_info => "OpenSSL--->DoveSSL",
#    },
#    {
#        $cmd_param => "-c $ca -k $key -p $port -S",
#        $test_info => "DoveSSL--->OpenSSL",
#    },
    {
        $cmd_param => "-c $ca -k $key -p $port -C -S",
        $test_info => "OpenSSL--->OpenSSL",
    },
);

sub usage {
    print ("usage: $0 ");
    print ("\t\t\t\t-d (no args, debug mode)\n");
    print ("\t\t\t\t-h (no args, help)\n");
}

my $scount = 0;
my $acount = 0;
for my $tc (@testcase) {
    $acount++;
    $cmd_str = "sudo $test_cmd $tc->{$cmd_param}";
    if (!$opt_d) {
        $cmd_str .= " 1>/dev/null";
    }
    my $ret = system($cmd_str);
    $ret /= 256;
    if ($ret eq 0) {
        print("testcase $tc->{$test_info} succeed!\n");
        $scount++;
    } else {
        print("testcase $tc->{$test_info} failed! ret = $ret\n");
    }
}

print("Run $acount testcases, succeed $scount!\n");


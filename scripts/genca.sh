#!/bin/bash

set -e
key_bits=512
expire_days=10950
cli_conf="conf/client.conf"
subj=/C="CN"/ST="Liaoning"/L="Shenyang"/O="Neusoft"/OU="ntsc"/CN="ntsc"
subj2=/C="CN"/ST="Liaoning"/L="Shenyang"/O="NeusoftCERT"/OU="ntsc"/CN="ntsc"

cert_type=$1
out_dir=$2
if [ x$cert_type = "xca" ]; then
    if [ -z $out_dir ]; then
        echo "$0 out_dir"
        exit 1
    fi
#Root
    openssl genrsa -out $out_dir/ca.key $key_bits
    openssl req -x509 -newkey rsa:$key_bits -keyout $out_dir/ca.key -nodes -out $out_dir/ca.cer -subj $subj -days $expire_days
    exit 0
fi

ca_cer=`grep \"ca\" $cli_conf | cut -d ':' -f 2 | cut -d '"' -f 2`
cli_cer=`grep \"cert\" $cli_conf | cut -d ':' -f 2 | cut -d '"' -f 2`
cli_key=`grep \"key\" $cli_conf | cut -d ':' -f 2 | cut -d '"' -f 2`
#ser_cer=`grep ssl-cert /etc/my.cnf | cut -d '=' -f 2`
#ser_key=`grep ssl-key /etc/my.cnf | cut -d '=' -f 2`

gen_cer_key()
{
    cer=$1
    key=$2

    ca_path=`dirname $ca_cer`
    openssl genrsa -out $key $key_bits
    openssl req -new -key $key -sha256 -out stg.csr -subj $subj2 -days $expire_days
    openssl x509 -req -in stg.csr -sha256 -out $cer -CA $ca_cer -CAkey $ca_path/ca.key -CAserial t_ssl_ca.srl -CAcreateserial -days $expire_days -extensions v3_req
    rm -f *.csr *.srl
}

gen_cer_key $cli_cer $cli_key
#gen_cer_key $ser_cer $ser_key

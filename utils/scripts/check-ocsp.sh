#!/bin/sh

OCSP_URL=$1
ISSUER=$2
SERIAL=$3

BASENAME=`basename $0`


usage() {
	echo "usage: $BASENAME responder-url issuer serial"
	exit 1
}

if [ -z "${OCSP_URL}" -o -z "${ISSUER}" -o -z "${SERIAL}" ]; then
	usage
fi

if [ ! -f $ISSUER ]; then
	echo "Can't open issuer certificate file"
	exit 1
fi

DER_REQUEST=`mktemp -q /tmp/${BASENAME}.req.XXXXXX`
if [ $? -ne 0 ]; then
	echo "$0: Can't create temporary file, exiting..."
	exit 1
fi

DER_RESPONSE=`mktemp -q /tmp/${BASENAME}.res.XXXXXX`
if [ $? -ne 0 ]; then
	echo "$0: Can't create temporary file, exiting..."
	exit 1
fi

# create OCSP request
openssl ocsp -reqout $DER_REQUEST -issuer $ISSUER -serial 0x$SERIAL -nonce 

# create base64-encoded OCSP request URI
B64_REQUEST=`openssl base64 -in $DER_REQUEST`

REQUEST_URI=$OCSP_URL/`echo $B64_REQUEST | sed 's/ //g'`

# send OCSP request to OCSP responder
curl -s -o $DER_RESPONSE $REQUEST_URI

# parse OCSP response
openssl ocsp -respin $DER_RESPONSE -noverify -text

# clean up
rm -f $DER_REQUEST $DER_RESPONSE

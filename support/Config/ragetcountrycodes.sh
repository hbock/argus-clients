#!/bin/bash
#
#  Argus Client Support Software.  Tools to support tools for Argus data.
#  Copyright (C) 2000-2008 QoSient, LLC.
#  All Rights Reserved
#
#  ragetcountrycodes.sh
#
#  Script to get all the delegated address space allocations directly
#  from the proper registries and consolidate for ra* support for
#  printing country codes.
#  
#  This should be done periodcially, say weekly as the delegated
#  address space does change.
#
#  Carter Bullard <carter@qosient.com>
#

wget ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest
wget ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest
wget ftp://ftp.arin.net/pub/stats/arin/delegated-arin-latest
wget ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest
wget ftp://ftp.ripe.net/ripe/stats/delegated-ripencc-latest
wget ftp://ftp.apnic.net/pub/stats/iana/delegated-iana-latest

fgrep ipv4 delegated*latest > delegated-ipv4-latest

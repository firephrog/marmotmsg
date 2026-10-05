#!/bin/bash
# A configuration change rebuilds nginx too: put the https server back.
exec /var/app/current/.platform/hooks/postdeploy/10-https.sh

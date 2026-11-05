#!/bin/bash
# A configuration change (e.g. MARMOT_HOST) re-runs the relay setup too.
exec /var/app/current/.platform/hooks/postdeploy/20-turn.sh

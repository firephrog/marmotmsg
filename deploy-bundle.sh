#!/bin/sh
# Builds the Elastic Beanstalk bundle: the server directory as the root, plus the client.
# No node_modules (EB installs Linux builds), data, .env or tests.
set -e
cd "$(dirname "$0")"
out="${1:-marmot-bundle.zip}"
stage=$(mktemp -d)
cp server/server.js server/db.js server/seal.js server/discord.js server/package.json server/package-lock.json "$stage"/
cp -r server/.ebextensions server/.platform "$stage"/
mkdir -p "$stage/client" && cp client/Marmot.html "$stage/client/"
rm -f "$out"
# bsdtar writes real zips with forward-slash paths; Git Bash's GNU tar cannot write zips at all
TAR=tar; [ -x /c/Windows/System32/tar.exe ] && TAR=/c/Windows/System32/tar.exe
(cd "$stage" && $TAR -a -cf bundle.zip server.js db.js seal.js discord.js package.json package-lock.json .ebextensions .platform client)
mv "$stage/bundle.zip" "$out"
rm -rf "$stage"
echo "built $out"

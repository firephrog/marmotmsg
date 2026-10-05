#!/bin/sh
# First deploy of the Marmot beta to Elastic Beanstalk. HTTPS is on the instance itself: a Let's
# Encrypt certificate for <elastic-ip>.sslip.io (see server/.platform/hooks/postdeploy/10-https.sh).
#
#   sh deploy-eb.sh            create everything (run once)
#   sh deploy-eb.sh update     deploy a new build to the existing environment
#
# Creates in us-east-1: EB application "marmot", environment "marmot-beta" (single t3.micro,
# no load balancer).
# Secrets: MARMOT_DB_KEY is generated here; DISCORD_TOKEN is copied from server/.env if set.
# Both live only in the EB environment properties; they are never printed.
set -e
cd "$(dirname "$0")"
APP=marmot ENV=marmot-beta STACK="64bit Amazon Linux 2023 v6.11.9 running Node.js 22"
LABEL="v0.4.0-$(date +%Y%m%d%H%M%S)"
TMP=$(mktemp -d)
# Git Bash on Windows: aws.exe needs a Windows path inside file://… (plain arguments are converted, file:// ones are not)
FTMP=$(cygpath -m "$TMP" 2>/dev/null || echo "$TMP")

sh deploy-bundle.sh "$TMP/bundle.zip"
BUCKET=$(aws elasticbeanstalk create-storage-location --query S3Bucket --output text)
aws s3 cp "$TMP/bundle.zip" "s3://$BUCKET/$APP/$LABEL.zip" --only-show-errors
if [ "$1" != update ] && [ -z "$(aws elasticbeanstalk describe-applications --application-names $APP --query 'Applications[0].ApplicationName' --output text | grep -v None)" ]; then
  aws elasticbeanstalk create-application --application-name $APP \
    --description "Marmot: Signal-protocol messenger (beta)" --output text --query Application.ApplicationName
fi
aws elasticbeanstalk create-application-version --application-name $APP --version-label "$LABEL" \
  --source-bundle "S3Bucket=$BUCKET,S3Key=$APP/$LABEL.zip" --process --output text --query ApplicationVersion.VersionLabel

if [ "$1" = update ]; then
  aws elasticbeanstalk update-environment --environment-name $ENV --version-label "$LABEL" --output text --query Status
  aws elasticbeanstalk wait environment-updated --environment-names $ENV
  echo "deployed $LABEL"; rm -rf "$TMP"; exit 0
fi

node -e "
const fs=require('fs'),crypto=require('crypto');
let env={};try{env=Object.fromEntries(fs.readFileSync('server/.env','utf8').split(/\r?\n/).filter(l=>/^[A-Z_]+=./.test(l)).map(l=>[l.slice(0,l.indexOf('=')),l.slice(l.indexOf('=')+1).trim()]))}catch(e){}
const o=(Namespace,OptionName,Value)=>({Namespace,OptionName,Value}),A='aws:elasticbeanstalk:application:environment';
const opts=[
 o('aws:elasticbeanstalk:environment','EnvironmentType','SingleInstance'),
 o('aws:elasticbeanstalk:environment','ServiceRole','aws-elasticbeanstalk-service-role'),
 o('aws:autoscaling:launchconfiguration','IamInstanceProfile','aws-elasticbeanstalk-ec2-role'),
 o('aws:ec2:instances','InstanceTypes','t3.micro'),
 o('aws:elasticbeanstalk:healthreporting:system','SystemType','enhanced'),
 o(A,'NODE_ENV','production'),o(A,'MARMOT_DATA','/var/marmot-data'),o(A,'TRUST_PROXY','1'),
 o(A,'MARMOT_DB_KEY',crypto.randomBytes(32).toString('hex'))];
for(const k of ['DISCORD_TOKEN','TURN_URLS','TURN_SECRET','STUN_URLS'])if(env[k])opts.push(o(A,k,env[k]));
fs.writeFileSync(process.argv[1],JSON.stringify(opts));
" "$FTMP/options.json"
aws elasticbeanstalk create-environment --application-name $APP --environment-name $ENV --cname-prefix $ENV \
  --solution-stack-name "$STACK" --version-label "$LABEL" --option-settings "file://$FTMP/options.json" \
  --output text --query EnvironmentName
rm -f "$TMP/options.json"
echo "waiting for the environment (5-10 minutes)…"
aws elasticbeanstalk wait environment-exists --environment-names $ENV
CNAME=$(aws elasticbeanstalk describe-environments --environment-names $ENV --query "Environments[0].CNAME" --output text)
echo "EB: http://$CNAME"

rm -rf "$TMP"
IP=$(aws elasticbeanstalk describe-environments --environment-names $ENV --query "Environments[0].EndpointURL" --output text)
echo "HTTPS: https://$(echo "$IP" | tr . -).sslip.io (once the certificate is issued, a minute after the first deploy)"

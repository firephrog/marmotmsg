#!/bin/sh
# First deploy of the Marmot beta to Elastic Beanstalk, behind CloudFront for HTTPS
# (browsers only allow the microphone on secure pages, and there is no domain/ACM cert yet).
#
#   sh deploy-eb.sh            create everything (run once)
#   sh deploy-eb.sh update     deploy a new build to the existing environment
#
# Creates in us-east-1: EB application "marmot", environment "marmot-beta" (single t3.micro,
# no load balancer), and a CloudFront distribution in front of it.
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
 o(A,'NODE_ENV','production'),o(A,'MARMOT_DATA','/var/marmot-data'),o(A,'TRUST_PROXY','2'),
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

# CloudFront: no caching (CachingDisabled), every header/cookie/query passed through (AllViewer,
# which also carries Authorization and the WebSocket upgrade), http to the origin.
cat > "$TMP/cf.json" <<JSON
{"CallerReference":"$APP-$LABEL","Comment":"Marmot beta: HTTPS for $ENV","Enabled":true,"PriceClass":"PriceClass_100",
 "Origins":{"Quantity":1,"Items":[{"Id":"$ENV","DomainName":"$CNAME","CustomOriginConfig":{"HTTPPort":80,"HTTPSPort":443,
  "OriginProtocolPolicy":"http-only","OriginSslProtocols":{"Quantity":1,"Items":["TLSv1.2"]},"OriginReadTimeout":60,"OriginKeepaliveTimeout":60}}]},
 "DefaultCacheBehavior":{"TargetOriginId":"$ENV","ViewerProtocolPolicy":"redirect-to-https","Compress":true,
  "CachePolicyId":"4135ea2d-6df8-44a3-9df3-4b5a84be39ad","OriginRequestPolicyId":"216adef6-5c7f-47e4-b989-5492eafa07d3",
  "AllowedMethods":{"Quantity":7,"Items":["GET","HEAD","OPTIONS","PUT","POST","PATCH","DELETE"],"CachedMethods":{"Quantity":2,"Items":["GET","HEAD"]}}}}
JSON
DIST=$(aws cloudfront create-distribution --distribution-config "file://$FTMP/cf.json" --query "Distribution.[Id,DomainName]" --output text)
rm -rf "$TMP"
echo "CloudFront: $DIST (takes ~5 minutes to go live)"
echo "Beta URL: https://$(echo "$DIST" | awk '{print $2}')"

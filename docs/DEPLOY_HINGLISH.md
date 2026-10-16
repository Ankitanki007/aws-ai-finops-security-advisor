# AWS Console + CLI Deployment Guide (Hinglish)

Is guide ko order mein follow karo. Har step mein Console aur CLI dono diye hain. **Har resource ke liye Console ya CLI mein se ek raasta chuno; dono raaste mat chalao**, warna duplicate resources ban sakte hain. Region hamesha `ap-southeast-2` (Asia Pacific—Sydney) rakho.

Yeh setup ek account aur ek region scan karta hai. Lambda read-only findings banata hai aur private S3 report likhta hai. Koi auto-fix/remediation nahi hai.

## Step 0 — Account aur region confirm karo

**CLI:** AWS CLI v2 ke configured terminal mein:

```bash
aws --version
aws sts get-caller-identity --region ap-southeast-2
```

`Account` aur `Arn` ko check karo ki yahi intended AWS account hai. Account ID share karna zaroori nahi.

**Console:** AWS Management Console ke top-right account menu se account ID verify karo. Region selector se **Asia Pacific (Sydney) `ap-southeast-2`** chuno.

**Ruko agar:** `Unable to locate credentials`, access denied, ya galat account aaye. Access keys chat mein paste mat karna.

## Step 1 — Code package banao

Project root directory `aws-ai-finops-security-advisor` mein terminal kholo.

**CLI/local terminal:**

```bash
python3 -m unittest discover -s tests -v
./scripts/package.sh
```

Tests pass hone chahiye aur `build/lambda.zip` ban jana chahiye. Is ZIP ke andar `lambda_handler.py` root par hai; isi liye Lambda handler `lambda_handler.lambda_handler` hoga.

**Console:** AWS Console code package nahi banata. Upar ka local packaging step phir bhi zaroori hai; baad mein ZIP Lambda console mein upload karoge.

## Step 2 — Private report bucket banao

Account ID ke saath unique bucket name rakho. Example: `ai-finops-security-advisor-123456789012-ap-southeast-2`. Bucket name globally unique hona chahiye.

**CLI:** Pehle variables set karo (account ID apne Step 0 se automatically aayega):

```bash
export AWS_REGION=ap-southeast-2
export ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text --region "$AWS_REGION")"
export BUCKET="ai-finops-security-advisor-${ACCOUNT_ID}-ap-southeast-2"
aws s3api create-bucket --bucket "$BUCKET" --region "$AWS_REGION" --create-bucket-configuration LocationConstraint="$AWS_REGION"
aws s3api put-public-access-block --bucket "$BUCKET" --region "$AWS_REGION" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket "$BUCKET" --region "$AWS_REGION" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

Lifecycle policy banao taaki reports 30 din baad expire hon:

```bash
cat > /tmp/advisor-lifecycle.json <<'JSON'
{"Rules":[{"ID":"expire-reports-after-30-days","Status":"Enabled","Filter":{"Prefix":"reports/"},"Expiration":{"Days":30}}]}
JSON
aws s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" --region "$AWS_REGION" --lifecycle-configuration file:///tmp/advisor-lifecycle.json
```

**Console:** S3 → **Create bucket** → bucket name upar wale format mein → Region Sydney. **Block all public access** enabled rehne do. Create karo. Bucket open karke **Properties → Default encryption → Edit** mein SSE-S3/AES-256 set karo. **Management → Create lifecycle rule** → rule name `expire-reports-after-30-days`, prefix `reports/`, expire current versions after 30 days. Bucket ko public mat karo.

**Verify:** CLI: `aws s3api get-public-access-block --bucket "$BUCKET" --region "$AWS_REGION"` aur `aws s3api get-bucket-encryption --bucket "$BUCKET" --region "$AWS_REGION"`. Console mein bucket ke Properties par public access blocked aur default encryption enabled dikhna chahiye.

## Step 3 — Lambda execution role aur minimum permissions

Lambda ko AWS par read-only scan karne, logs likhne aur apne S3 bucket mein report upload karne ke liye role chahiye. Role account ke ussi resources tak limited hai jo policy mein listed hain.

**CLI:** Trust policy aur role banao:

```bash
cat > /tmp/advisor-lambda-trust.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
JSON
aws iam create-role --role-name AIFinOpsAdvisorLambdaRole --assume-role-policy-document file:///tmp/advisor-lambda-trust.json
aws iam attach-role-policy --role-name AIFinOpsAdvisorLambdaRole --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

Ab custom read/report policy create karo. `BUCKET` Step 2 mein set hona chahiye:

```bash
cat > /tmp/advisor-lambda-policy.json <<JSON
{
  "Version":"2012-10-17",
  "Statement":[
    {"Sid":"ReadRegionalInventory","Effect":"Allow","Action":["ec2:DescribeAddresses","ec2:DescribeInstances","ec2:DescribeSecurityGroups","ec2:DescribeVolumes","cloudwatch:GetMetricStatistics","rds:DescribeDBInstances"],"Resource":"*"},
    {"Sid":"ReadAccountSignals","Effect":"Allow","Action":["iam:GetAccountSummary","s3:ListAllMyBuckets"],"Resource":"*"},
    {"Sid":"ReadS3PolicyStatus","Effect":"Allow","Action":"s3:GetBucketPolicyStatus","Resource":"arn:aws:s3:::*"},
    {"Sid":"WriteOnlyAdvisorReports","Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::$BUCKET/reports/*"}
  ]
}
JSON
aws iam put-role-policy --role-name AIFinOpsAdvisorLambdaRole --policy-name AIFinOpsAdvisorPermissions --policy-document file:///tmp/advisor-lambda-policy.json
export LAMBDA_ROLE_ARN="$(aws iam get-role --role-name AIFinOpsAdvisorLambdaRole --query Role.Arn --output text)"
```

**Console:** IAM → Roles → **Create role** → Trusted entity `AWS service` → Use case `Lambda` → next. `AWSLambdaBasicExecutionRole` managed policy attach karo. Role create karke role ke **Add permissions → Create inline policy → JSON** mein `/tmp/advisor-lambda-policy.json` ke equivalent policy paste karo; `BUCKET_NAME` ko apne exact bucket name se badlo. Policy ka `PutObject` resource sirf `arn:aws:s3:::BUCKET_NAME/reports/*` ho. Role ka naam `AIFinOpsAdvisorLambdaRole` rakh sakte ho.

**Verify:** IAM role ke Trust relationships mein `lambda.amazonaws.com` aur Permissions mein basic logging + custom policy dikhni chahiye.

## Step 4 — Lambda function banao

**CLI:** `build/lambda.zip` ready aur role ARN set hone ke baad:

```bash
aws lambda create-function \
  --region ap-southeast-2 \
  --function-name ai-finops-security-advisor \
  --runtime python3.12 \
  --handler lambda_handler.lambda_handler \
  --role "$LAMBDA_ROLE_ARN" \
  --timeout 60 \
  --memory-size 256 \
  --zip-file fileb://build/lambda.zip \
  --environment "Variables={REPORT_BUCKET=$BUCKET,SCAN_REGION=ap-southeast-2,ENABLE_AI_SUMMARY=false,BEDROCK_MODEL_ID=amazon.nova-micro-v1:0}"
```

**Console:** Lambda → Functions → **Create function** → Author from scratch. Name `ai-finops-security-advisor`; Runtime Python 3.12; Architecture x86_64; permissions mein existing role `AIFinOpsAdvisorLambdaRole` select karo. Function banne ke baad **Code → Upload from → .zip file** se `build/lambda.zip` upload karo. Runtime settings mein handler `lambda_handler.lambda_handler` confirm karo; Configuration → General configuration → Edit mein timeout 1 minute aur memory 256 MB set karo. Configuration → Environment variables mein:

| Key | Value |
|---|---|
| `REPORT_BUCKET` | Step 2 ka exact bucket name |
| `SCAN_REGION` | `ap-southeast-2` |
| `ENABLE_AI_SUMMARY` | `false` (pehla run deterministic, no model call) |
| `BEDROCK_MODEL_ID` | `amazon.nova-micro-v1:0` |

**Verify:** Lambda page par function state `Active` aur handler/runtime correct hon.

## Step 5 — Pehla scan manually chalao

Pehle manually verify karna hai, daily schedule abhi mat banao.

**CLI:**

```bash
aws lambda invoke --region ap-southeast-2 --function-name ai-finops-security-advisor /tmp/advisor-invoke.json
cat /tmp/advisor-invoke.json
aws s3 ls "s3://$BUCKET/reports/" --recursive --region ap-southeast-2
```

Invoke response mein `statusCode: 200`, report key aur summary aani chahiye. Report list mein `reports/YYYY/MM/DD/scan-....json` dikhega.

**Console:** Lambda function → **Test** tab → event JSON `{}` → Test. Execution result mein `statusCode` 200 dekho. S3 → apna bucket → `reports/` prefix mein JSON report dekho/download karo. Report mein resource IDs hote hain; ise private hi rakho.

**Agar error aaye:** Lambda Monitor → CloudWatch logs kholo. `AccessDenied` ho to role policy / bucket ARN check karo; timeout ho to report se pehle log check karo. Credentials/secret env vars add karne ki zaroorat nahi.

## Step 6 — Daily schedule (optional, test successful hone ke baad)

Schedule har din Australia/Sydney timezone mein ek baar Lambda invoke karega. Yeh extra service charge generally bahut chhota ho sakta hai, lekin AWS pricing/account free usage ke hisaab se bill check karna.

**CLI:** Schedule group banao:

```bash
aws scheduler create-schedule-group --name ai-finops-advisor --region ap-southeast-2
export GROUP_ARN="arn:aws:scheduler:ap-southeast-2:${ACCOUNT_ID}:schedule-group/ai-finops-advisor"
export FUNCTION_ARN="$(aws lambda get-function --function-name ai-finops-security-advisor --region ap-southeast-2 --query Configuration.FunctionArn --output text)"
```

Scheduler ka assume-role trust banao (specific schedule group se hi assume karne ki condition):

```bash
cat > /tmp/advisor-scheduler-trust.json <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"scheduler.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"ArnEquals":{"aws:SourceArn":"$GROUP_ARN"},"StringEquals":{"aws:SourceAccount":"$ACCOUNT_ID"}}}]}
JSON
aws iam create-role --role-name AIFinOpsAdvisorSchedulerRole --assume-role-policy-document file:///tmp/advisor-scheduler-trust.json
export SCHEDULER_ROLE_ARN="$(aws iam get-role --role-name AIFinOpsAdvisorSchedulerRole --query Role.Arn --output text)"
cat > /tmp/advisor-invoke-policy.json <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"$FUNCTION_ARN"}]}
JSON
aws iam put-role-policy --role-name AIFinOpsAdvisorSchedulerRole --policy-name InvokeAdvisorLambda --policy-document file:///tmp/advisor-invoke-policy.json
cat > /tmp/advisor-target.json <<JSON
{"Arn":"$FUNCTION_ARN","RoleArn":"$SCHEDULER_ROLE_ARN","Input":"{}"}
JSON
aws scheduler create-schedule \
  --region ap-southeast-2 \
  --group-name ai-finops-advisor \
  --name daily-scan \
  --schedule-expression 'cron(0 9 * * ? *)' \
  --schedule-expression-timezone Australia/Sydney \
  --flexible-time-window '{"Mode":"OFF"}' \
  --target file:///tmp/advisor-target.json
```

**Console:** Amazon EventBridge → Scheduler → **Create schedule**. Name `daily-scan`; schedule group create/select `ai-finops-advisor`; recurring schedule `cron(0 9 * * ? *)`; timezone `Australia/Sydney`; flexible time window Off. Target type AWS Lambda `ai-finops-security-advisor`; input `{}`. Permissions mein Scheduler ke liye naya invoke role create karne ka option chuno. Review karke Create schedule.

**Verify:** EventBridge Scheduler → Schedules mein schedule `ENABLED` dikhna chahiye. Agle run ke baad S3 reports prefix aur Lambda CloudWatch logs check karo. Ek immediate test pehle hi Step 5 mein kar chuke ho.

## Optional — AI summary on karna

Pehle deterministic scan chalana recommended hai. Nova Micro invocation par model pricing apply ho sakti hai. AI summary findings ke IDs hata kar bhejti hai, par findings/evidence text mein infrastructure context ho sakta hai. Account ki data policy ke mutabik hi enable karo.

1. Bedrock console mein Sydney (`ap-southeast-2`) mein Amazon Nova Micro model access/availability confirm karo.
2. Lambda role policy mein `bedrock:InvokeModel` allow karo, resource: `arn:aws:bedrock:ap-southeast-2::foundation-model/amazon.nova-micro-v1:0`.
3. Lambda environment variable `ENABLE_AI_SUMMARY=true` karo.
4. Ek manual test invoke karke S3 report ke `ai_summary` aur CloudWatch logs verify karo. Disable karne ke liye variable wapas `false`.

**Console:** IAM role inline policy mein yeh statement add karo, phir Lambda → Configuration → Environment variables mein `ENABLE_AI_SUMMARY` ko `true` set karo. **CLI:** policy JSON mein alag statement add karke `put-role-policy` dobara chalao; phir `aws lambda update-function-configuration --region ap-southeast-2 --function-name ai-finops-security-advisor --environment "Variables={REPORT_BUCKET=$BUCKET,SCAN_REGION=ap-southeast-2,ENABLE_AI_SUMMARY=true,BEDROCK_MODEL_ID=amazon.nova-micro-v1:0}"`.

## Cost aur scope

Is design mein EC2/RDS/EKS/NAT Gateway/AWS Config/GuardDuty create nahi hote. Lambda, Scheduler, S3 storage/requests, CloudWatch logs aur optional Bedrock inference account/region/pricing ke hisaab se charge ho sakte hain. Free tier ko guaranteed assume mat karo; deploy ke baad Billing/Cost Explorer mein actual usage dekho. Lambda default VPC ke bahar rahega, isliye NAT Gateway ki zaroorat nahi.

Scanner Lambda role ki permissions se isi account ka inventory scan karega. Region-based EC2/EBS/SG/RDS/metrics Sydney tak limited hain; root MFA aur S3 policy status account-wide checks hain. Cross-account roles configure nahi kiye gaye.

## Cleanup (sirf is project ke resources)

Pehle Scheduler schedule disable/delete karo; phir Lambda function; phir Scheduler aur Lambda IAM roles/policies; aakhir mein report bucket aur reports. Bucket delete karne se pehle uske contents verify karo—bucket mein doosra data ho to delete mat karo. Console se har resource ke exact project name ko verify karke delete karo. CLI cleanup commands sirf tab chalao jab in names ki ownership confirm kar lo; bucket delete destructive hai:

```bash
aws scheduler delete-schedule --region ap-southeast-2 --group-name ai-finops-advisor --name daily-scan
aws scheduler delete-schedule-group --region ap-southeast-2 --name ai-finops-advisor
aws lambda delete-function --region ap-southeast-2 --function-name ai-finops-security-advisor
```

In teen steps ke baad IAM mein exact project roles `AIFinOpsAdvisorSchedulerRole` aur `AIFinOpsAdvisorLambdaRole` aur unki inline policies delete karo. Bucket ko tabhi remove karo jab contents inspect kar liye hon aur sab project reports delete karne ka faisla kiya ho. Is guide ka cleanup intentionally S3 bucket delete nahi karta.

## Troubleshooting quick map

- `Unable to locate credentials`: CLI profile/SSO login set karo; keys source code ya chat mein mat rakho.
- `AccessDenied` on `create-*`: deploy karne wale identity ko required IAM permissions chahiye; admin policy blindly attach mat karo.
- Lambda `AccessDenied` while writing: Lambda role ke report `PutObject` ARN mein bucket/prefix exact match karo.
- Bedrock summary missing: `ENABLE_AI_SUMMARY=false` expected behavior hai; true karne ke baad model access, region, permission aur logs check karo.
- Empty findings: iska matlab sirf configured checks ko findings nahi mili; complete compliance/security clearance nahi.

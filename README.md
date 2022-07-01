# s3-bucket-object-ownership-config-check
This is a sample [AWS Config Custom Lambda Rule](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_lambda-functions.html) for detecting Amazon S3 Buckets that have ACLs enabled and are not enforcing object ownership. 

```Disclaimer```: This is just a sample, not intended for production usage. 

## Background
Amazon S3 has a number of different ways to [control access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html) to content. Access Control Lists allow management of access to buckets and objects via grants to AWS accounts or groups, allowing for a variety of filesystem like file ownership and access rules. However, a majority of modern use cases for Amazon S3 no longer require the use of ACLs and can be solved via one of the other access patterns. AWS recommends disabling ACLs unless explicitly required for your use case. ACLs are disabled on new S3 buckets by default, however you can [disable ACLs ](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html) for any S3 buckets that have ACLs enabled currently. 

This AWS Config Custom Lambda Rule will detect which S3 buckets are not enforcing object ownership (ACLs disabled).


## Lambda Configuration
Starting point for Lambda function configuration:
- Runtime: Python 3.9
- Architecture: arm64
- Handler: lambda_function.lambda_handler
- Memory: 512MB
- Timeout: 5 minutes

The Lambda memory and timeout settings will be driven primarily based on how many S3 buckets exist in your AWS account. A estimate for runtime would be 125ms per S3 bucket.

### Lambda Execution Role
Your Lambda function will likely have an auto-created policy based on AWSLambdaBasicExecutionRole that allows, at minimum:
- logs:CreateLogGroup
- logs:CreateLogStream
- logs:PutLogEvents

To allow the Lambda function to interact with AWS Config, attach the following AWS Managed Policies:
- AWSConfigRulesExecutionRole

In addition, you should attach a policy that allows the following permissions for all S3 buckets in scope for assessment:
- s3:GetBucketOwnershipControls

### Lambda Code
See sample code in [src/lambda_function.py](src/lambda_function.py).

Deploy the Lambda function

## Config Rule Configuration
1. Add a Rule in AWS Config, select Custom Lambda Rule.
1. Fill in the Rule configuration
    - Name: s3-bucket-ownership-enforced
    - Description: Check that S3 bucket object ownership is enforced
    - AWS Lambda function ARN: _ARN of your Lambda function_
    - Trigger Type: Periodic
    - Frequency: 24 hours (recommended)
1. Review and save
Note: The Lambda function code also supports change notification based evaluation, however AWS Config does not currently record Object Ownership Control as part of the S3 Configuration item, so change notification is not triggered based on a change in this setting.

import boto3
import json

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False
DEFAULT_RESOURCE_TYPE = 'AWS::S3::Bucket'

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event):
    """Return the service boto client. It should be used instead of directly calling the client.
    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       )

def get_assume_role_credentials(role_arn):
    sts_client = boto3.client('sts')
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response['Credentials']
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex


# Helper function used to validate input
def check_defined(reference, reference_name):
    if not reference:
        raise Exception('Error: ', reference_name, 'is not defined')
    return reference

# Check whether the message is OversizedConfigurationItemChangeNotification or not
def is_oversized_changed_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'OversizedConfigurationItemChangeNotification'

# Get configurationItem using getResourceConfigHistory API
# in case of OversizedConfigurationItemChangeNotification
def get_configuration(resource_type, resource_id, configuration_capture_time):
    result = AWS_CONFIG_CLIENT.get_resource_config_history(
        resourceType=resource_type,
        resourceId=resource_id,
        laterTime=configuration_capture_time,
        limit=1)
    configurationItem = result['configurationItems'][0]
    return convert_api_configuration(configurationItem)

# Convert from the API model to the original invocation model
def convert_api_configuration(configurationItem):
    for k, v in configurationItem.items():
        if isinstance(v, datetime.datetime):
            configurationItem[k] = str(v)
    configurationItem['awsAccountId'] = configurationItem['accountId']
    configurationItem['ARN'] = configurationItem['arn']
    configurationItem['configurationStateMd5Hash'] = configurationItem['configurationItemMD5Hash']
    configurationItem['configurationItemVersion'] = configurationItem['version']
    configurationItem['configuration'] = json.loads(configurationItem['configuration'])
    if 'relationships' in configurationItem:
        for i in range(len(configurationItem['relationships'])):
            configurationItem['relationships'][i]['name'] = configurationItem['relationships'][i]['relationshipName']
    return configurationItem

# Based on the type of message get the configuration item
# either from configurationItem in the invoking event
# or using the getResourceConfigHistory API in getConfiguration function.
def get_configuration_item(invokingEvent):
    check_defined(invokingEvent, 'invokingEvent')
    if is_oversized_changed_notification(invokingEvent['messageType']):
        configurationItemSummary = check_defined(invokingEvent['configurationItemSummary'], 'configurationItemSummary')
        return get_configuration(configurationItemSummary['resourceType'], configurationItemSummary['resourceId'], configurationItemSummary['configurationItemCaptureTime'])
    return check_defined(invokingEvent['configurationItem'], 'configurationItem')

# Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configurationItem, event):
    try:
        check_defined(configurationItem, 'configurationItem')
        check_defined(event, 'event')
    except:
        return True
    status = configurationItem['configurationItemStatus']
    eventLeftScope = event['eventLeftScope']
    if status == 'ResourceDeleted':
        print("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")
    return (status == 'OK' or status == 'ResourceDiscovered') and not eventLeftScope

# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(message_type):
    return message_type == 'ScheduledNotification'

def get_resources(applicable_resource_type, next_token):
    resources = AWS_CONFIG_CLIENT.list_discovered_resources(resourceType=applicable_resource_type, nextToken=next_token)
    return resources;

def evaluate_parameters(rule_parameters):
    # Not applicable for this example...
    # if 'applicableResourceType' not in rule_parameters:
    #     raise ValueError('The parameter with "applicableResourceType" as key must be defined.')
    # if not rule_parameters['applicableResourceType']:
    #    raise ValueError('The parameter "applicableResourceType" must have a defined value.')
    return rule_parameters

# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, timestamp, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.
    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule (default DEFAULT_RESOURCE_TYPE)
    annotation -- an annotation to be added to the evaluation (default None)
    """
    eval_cc = {}
    if annotation:
        eval_cc['Annotation'] = annotation
    eval_cc['ComplianceResourceType'] = resource_type
    eval_cc['ComplianceResourceId'] = resource_id
    eval_cc['ComplianceType'] = compliance_type
    eval_cc['OrderingTimestamp'] = timestamp
    return eval_cc

# Get the S3 Bucket Object Ownership Control setting
def get_s3_ownership(bucket):
    try: 
        result = S3_CLIENT.get_bucket_ownership_controls(Bucket=bucket)
        actual = result['OwnershipControls']['Rules'][0]['ObjectOwnership']
    except Exception as err:
        if "OwnershipControlsNotFoundError" in str(err):
            # Bucket was created before OwnershipControls were released, no setting in place
            actual = None
        else:
            # Other unknown error...
            print(repr(err))
            actual = None
    return actual

# Evaluates the configuration items in the snapshot and returns the compliance value to the handler.
def evaluate_compliance(expected, actual):
    compliance = 'NON_COMPLIANT' if actual != expected else 'COMPLIANT'
    annotation = None
    
    if actual is None:
        annotation = "Bucket object ownership control is undefined"
    elif actual != expected:
        annotation = "Bucket object ownership control is " + actual
    
    return compliance, annotation

def evaluate_s3_ownership_control_compliance(bucket, timestamp):
    actual = get_s3_ownership(bucket)
    compliance_value, annotation = evaluate_compliance('BucketOwnerEnforced', actual)
    print(DEFAULT_RESOURCE_TYPE, bucket, compliance_value, annotation)
    return build_evaluation(bucket, compliance_value, timestamp, annotation=annotation)

def lambda_handler(event, context):

    global AWS_CONFIG_CLIENT
    global S3_CLIENT

    evaluations = []
    rule_parameters = {}
    resource_count = 0
    max_count = 0

    check_defined(event, 'event')
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    valid_rule_parameters = evaluate_parameters(rule_parameters)

    compliance_value = 'NOT_APPLICABLE'

    AWS_CONFIG_CLIENT = get_client('config', event)
    S3_CLIENT = get_client('s3', event)
    if is_scheduled_notification(invoking_event['messageType']):
        timestamp = str(invoking_event['notificationCreationTime'])
        # For each resource found
        resources = get_resources(DEFAULT_RESOURCE_TYPE, '');
        
        while True:
            for resource in resources['resourceIdentifiers']:
                resource_id = resource['resourceId']
                evaluations.append(evaluate_s3_ownership_control_compliance(resource_id, timestamp))
                
            # Get any additional resources
            if 'NextToken' in resources:
                resources = get_resources(DEFAULT_RESOURCE_TYPE, resources['NextToken'])
            else:
                break
    else:
        configuration_item = get_configuration_item(invoking_event)
        resource_id = invoking_event['configurationItem']['resourceId']
        timestamp = str(configuration_item['configurationItemCaptureTime'])
        
        if is_applicable(configuration_item, event):
            evaluations.append(evaluate_s3_ownership_control_compliance(resource_id, timestamp))
        else:
            evaluations.append(build_evaluation(resource_id, compliance_value, timestamp, annotation=f'Rule only applies to {DEFAULT_RESOURCE_TYPE}'))
        
    response = AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluations, ResultToken=event['resultToken'])
    print(response)
import json
import boto3
import base64
import gzip
import uuid
from datetime import datetime

# AWS Clients
sns = boto3.client('sns', region_name='us-east-1')
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

# Configuration
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:675139392921:mini-soc-alerts'
DYNAMODB_TABLE = 'mini-soc-incidents'
FAILED_LOGIN_THRESHOLD = 3

# In-memory failed login tracker
failed_logins = {}

def lambda_handler(event, context):
    log_data = event['awslogs']['data']
    compressed = base64.b64decode(log_data)
    uncompressed = gzip.decompress(compressed)
    log_events = json.loads(uncompressed)
    
    for log_event in log_events['logEvents']:
        try:
            event_message = json.loads(log_event['message'])
            analyze_event(event_message)
        except Exception as e:
            print(f"Error processing event: {e}")
    
    return {'statusCode': 200, 'body': 'Analysis complete'}

def analyze_event(event):
    event_name = event.get('eventName', '')
    user_identity = event.get('userIdentity', {})
    source_ip = event.get('sourceIPAddress', 'Unknown')
    user_type = user_identity.get('type', '')
    username = user_identity.get('userName', 'Unknown')
    
    # Rule 1 — Root Account Usage (Critical)
    if user_type == 'Root':
        trigger_alert(
            incident_type='Root Account Usage',
            severity='CRITICAL',
            description=f'Root account was used to perform: {event_name}',
            source_ip=source_ip,
            username='root'
        )
    
    # Rule 2 — Failed Login Attempts (High)
    if event_name == 'ConsoleLogin':
        response_elements = event.get('responseElements', {})
        if response_elements.get('ConsoleLogin') == 'Failure':
            failed_logins[source_ip] = failed_logins.get(source_ip, 0) + 1
            if failed_logins[source_ip] >= FAILED_LOGIN_THRESHOLD:
                trigger_alert(
                    incident_type='Brute Force Login Attempt',
                    severity='HIGH',
                    description=f'Failed login attempts from IP: {source_ip}',
                    source_ip=source_ip,
                    username=username
                )
    
    # Rule 3 — Unauthorized IAM Changes (High)
    iam_events = [
        'CreateUser', 'DeleteUser', 'AttachUserPolicy',
        'DetachUserPolicy', 'CreateAccessKey', 'UpdateLoginProfile'
    ]
    if event_name in iam_events:
        trigger_alert(
            incident_type='Unauthorized IAM Change',
            severity='HIGH',
            description=f'IAM modification detected: {event_name} by {username}',
            source_ip=source_ip,
            username=username
        )
    
    # Rule 4 — Public S3 Bucket (Critical)
    if event_name == 'PutBucketAcl':
        request_params = event.get('requestParameters', {})
        if 'public' in str(request_params).lower():
            trigger_alert(
                incident_type='Public S3 Bucket Exposure',
                severity='CRITICAL',
                description=f'S3 bucket made public by {username}',
                source_ip=source_ip,
                username=username
            )
    
    # Rule 5 — Privilege Escalation (Critical)
    privilege_events = ['AttachRolePolicy', 'PutRolePolicy', 'CreatePolicy', 'SetDefaultPolicyVersion']
    if event_name in privilege_events:
        trigger_alert(
            incident_type='Privilege Escalation Attempt',
            severity='CRITICAL',
            description=f'Privilege escalation detected: {event_name} by {username}',
            source_ip=source_ip,
            username=username
        )
    
    # Rule 6 — Suspicious Region Activity (Medium)
    allowed_regions = ['us-east-1']
    event_region = event.get('awsRegion', '')
    if event_region and event_region not in allowed_regions:
        trigger_alert(
            incident_type='Suspicious Region Activity',
            severity='MEDIUM',
            description=f'Activity detected in unusual region: {event_region} by {username}',
            source_ip=source_ip,
            username=username
        )

def trigger_alert(incident_type, severity, description, source_ip, username):
    timestamp = datetime.utcnow().isoformat()
    incident_id = str(uuid.uuid4())
    
    # Save to DynamoDB
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.put_item(Item={
        'incident_id': incident_id,
        'timestamp': timestamp,
        'incident_type': incident_type,
        'severity': severity,
        'description': description,
        'source_ip': source_ip,
        'username': username,
        'status': 'OPEN'
    })
    
    # Send SNS Alert
    message = f"""
🚨 MINI SOC SECURITY ALERT

Incident ID: {incident_id}
Severity: {severity}
Type: {incident_type}
Description: {description}
Source IP: {source_ip}
Username: {username}
Timestamp: {timestamp}
Status: OPEN

Please investigate immediately.
— Mini SOC Auto Alert System
    """
    
    subject = f"[{severity}] Mini SOC Alert: {incident_type}"
    
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject=subject
    )
    
    print(f"Alert triggered: {incident_type} | Severity: {severity}")
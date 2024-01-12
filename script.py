import boto3
from datetime import datetime, timedelta
import pytz
import json
import requests

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError("Type not serializable")

def get_ip_info(ip):
    """ Retrieves country and city information for an IP address using ipinfo.io. """
    # Replace 'YOUR_ACCESS_TOKEN' with your access token for ipinfo.io
    response = requests.get(f"https://ipinfo.io/{ip}?token=YOUR_ACCESS_TOKEN")
    if response.status_code == 200:
        data = response.json()
        country = data.get('country', 'Unknown')
        city = data.get('city', 'Unknown')
        return country, city
    return "Unknown", "Unknown"

def get_event_ips(event_name, email, days, region):
    # Create a CloudTrail client
    client = boto3.client('cloudtrail', region_name=region)

    # Set the time range
    end_time = datetime.now(pytz.utc)
    start_time = end_time - timedelta(days=days)

    print(f"Analyzing '{event_name}' events for {email} from {start_time} to {end_time} in {region}...")

    # Create a paginator
    paginator = client.get_paginator('lookup_events')

    ip_addresses = set()

    # Retrieve and process events
    page_iterator = paginator.paginate(
        LookupAttributes=[
            {
                'AttributeKey': 'EventName',
                'AttributeValue': event_name
            }
        ],
        StartTime=start_time,
        EndTime=end_time,
    )

    for page in page_iterator:
        for event in page['Events']:
            event_data = json.loads(event.get('CloudTrailEvent', '{}'))
            user_identity = event_data.get('userIdentity', {})
            event_username = extract_username(user_identity)
            ip_address = event_data.get('sourceIPAddress')

            # Check if the email matches
            if event_username and (event_username == email or event_username.endswith(f"@{email}")) and ip_address:
                ip_addresses.add(ip_address)

    return ip_addresses

def extract_username(user_identity):
    """ Extracts the username from the userIdentity data. """
    if 'userName' in user_identity:
        return user_identity['userName']
    if 'arn' in user_identity and user_identity['type'] == 'AssumedRole':
        return user_identity['arn'].split('/')[-1]
    if 'principalId' in user_identity and ':' in user_identity['principalId']:
        return user_identity['principalId'].split(':')[1]
    return None

# User input
event_name = input("Enter Event Name for filtering (e.g., ConsoleLogin): ")
emails = input("Enter IAM username for analysis (comma-separated): ").split(',')
days = int(input("Enter the number of days for analysis: "))
aws_region = input("Enter the AWS region for search: ")

# Process each email
for email in emails:
    email = email.strip()  # Remove any whitespace around the email
    ip_addresses = get_event_ips(event_name, email, days, aws_region)

    # Output the results
    print(f"IP addresses, countries and cities for '{email}' associated with '{event_name}':")
    for ip_address in ip_addresses:
        country, city = get_ip_info(ip_address)
        print(f"{ip_address} (Country: {country}, City: {city})")

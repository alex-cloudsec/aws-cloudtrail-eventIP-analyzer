# AWS CloudTrail Event IP Analyzer

## Description
This Python script analyzes AWS CloudTrail logs to extract IP addresses associated with specific user email addresses for given event names. It is capable of handling multiple email addresses and provides detailed information about the geographic location (country and city) of each IP address.

## Features
- Filter CloudTrail events by specific event names (e.g., `ConsoleLogin`).
- Analyze events for multiple usernames/email addresses.
- Retrieve and display IP addresses associated with these events.
- Fetch and display the geographic location (country and city) of each IP address using ipinfo.io.

## Prerequisites
- Python 3.x
- AWS CLI installed and configured with appropriate permissions.
- Boto3 library installed (`pip install boto3`).
- Requests library installed (`pip install requests`).
- An access token from ipinfo.io (for IP geolocation).

## Usage
1. **Setup**: Ensure your AWS CLI is configured with the necessary permissions to interact with CloudTrail logs.
2. **Run the Script**: Execute the script in a Python environment. You will be prompted to enter:
   - Event Name for filtering.
   - Email addresses for analysis (comma-separated).
   - Number of days for log analysis.
   - AWS region for searching the logs.
3. **View Results**: The script outputs the IP addresses, along with their corresponding countries and cities, associated with the specified email addresses and event name.

![image](https://github.com/dvinskikh/aws-cloudtrail-eventIP-analyzer/assets/102820548/9e56348c-23b4-4aa5-894c-00c6217b61c4)

## Installation
Clone the repository to your local machine: `git clone https://github.com/dvinskikh/aws-cloudtrail-eventIP-analyzer.git`

## Dependencies
Install the required Python libraries: `pip install boto3 requests`

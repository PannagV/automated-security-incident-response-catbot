import requests
import json

# Test alerts to simulate different severities
test_alerts = [
    {'message': 'Regular system backup completed successfully', 'expected': 'Low'},
    {'message': 'Multiple failed login attempts detected on user account', 'expected': 'Medium'},
    {'message': 'Malware detected and quarantined on workstation', 'expected': 'High'},
    {'message': 'Ransomware encryption activity detected on file server', 'expected': 'Critical'}
]

print("Testing Alert Classifier with Sample Messages:")
print("=" * 50)

for alert in test_alerts:
    try:
        response = requests.post('http://localhost:5000/process_alert',
                               json={'message': alert['message'], 'classification_method': 'model'},
                               timeout=10)

        if response.status_code == 200:
            result = response.json()
            msg_short = alert['message'][:50] + "..." if len(alert['message']) > 50 else alert['message']
            print(f'Alert: {msg_short}')
            print(f'Expected: {alert["expected"]}, Predicted: {result.get("severity", "Unknown")}')
            print(f'Jira Ticket: {result.get("jira_ticket_id", "None")}')
            print(f'Slack Sent: {result.get("slack_success", False)}')
            print('---')
        else:
            print(f'Failed to process alert: {response.status_code} - {response.text}')
    except Exception as e:
        print(f'Error: {str(e)}')

print("Test completed!")
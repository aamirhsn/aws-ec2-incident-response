#!/usr/bin/env python3
import boto3, json, sys

eb = boto3.client('events')
if len(sys.argv) < 2:
    print("Usage: send_test_event.py <instance-id>")
    sys.exit(1)

instance_id = sys.argv[1]
with open('test_event.json') as fh:
    ev = json.load(fh)

# replace placeholder instance id with real one
ev['detail']['findings'][0]['Resources'][0]['Id'] = instance_id

resp = eb.put_events(Entries=[{
    'Source': ev['source'],
    'DetailType': ev['detail-type'],
    'Detail': json.dumps(ev['detail']),
    'EventBusName': 'default'
}])

print("PutEvents response:", resp)
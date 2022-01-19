# The purpose of this PTR Response script is to post data from PTR to sentinel
# Step 1: Configure sentinel and PTR Setting values in Edit Configuration section
# Step 2: Upload script as a Response Script
# Step 3: Create a Match Condition with the Responses --> Run a script
# Step 4: Select uploaded script

import os
import requests
import json
import datetime
import hashlib
import hmac
import base64

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

######################Edit Configuration######################
##############################################################
ptr_host="https://bbbbb.aaaaa.net" #https://2.2.2.2
ptr_key="1111111111111"
static_information="proofpoint_trap_siem"

# customer ID .... Log Analytics workspace ID
customer_id = 'xyz123'

# primary or the secondary Connected Sources client authentication key
shared_key = "abc123"

# name of the event that is being submitted / sentinel table name
log_type = 'ProofpointTest'
##############################################################
##############################################################

true = True
false = False

# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = str(string_to_hash).encode("utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'

    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)

    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print('Accepted')
    else:
        print("Response code: {}".format(response.status_code))

def execute_response():
    response_data=ptr.RESPONSE_DATA
    incidentID=response_data["IncidentID"]
    headers={'Authorization': ptr_key}
    api_string=ptr_host+"/api/incidents/%s.json"%str(incidentID)
    r1=requests.get(api_string,headers=headers,verify=False)
    try:
        assert r1.status_code in range(200,210), "incident api call failed"
    except Exception as e:
        print(e)
        return

    json_object=r1.json()

    for item in json_object["incident_field_values"]:
        if item["name"] == "Abuse Disposition":
            abuse_disposition = item["value"]
        if item["name"] == "Classification":
            classification = item["value"]

    for item in json_object ["events"][0]["emails"]:
        if item["abuseCopy"] == false :
            try:
                recipient=item["recipient"]["email"]
                messageid=item["messageId"]
                sender = item["sender"]["email"]
                subject = item["subject"]
                attachments = None
                urls = None
                if "attachments" in item:
                    attachments = item["attachments"]
                if "urls" in item:
                    urls = item["urls"]

            except Exception as e:
                print(e)
                return
        else:
            continue

    data_json = {}
    data_json["recipient"]=recipient
    data_json["messageid"]=messageid
    data_json["sender"]=sender
    data_json["subject"]=subject
    data_json["attachments"]= attachments
    data_json["urls"]= urls
    data_json["disposition"]= abuse_disposition
    data_json["classification"]= classification
    data_json["custom_data_static"]=static_information

    json_string = {"description":data_json, "overwrite":"true"}
    custom_short="%s - %s - %s"%(recipient, messageid, subject)
    print(custom_short)
    custom_long=str(json_string)

	dictEvent= {
    "table":"sample_table",
    "description":custom_long,
	"short_description": str(custom_short),
	}

    body = json.dumps(dictEvent)

    post_data(customer_id, shared_key, body, log_type)

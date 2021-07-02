import json
import os
import pprint
import ast 

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class WorkloadInfo(object):

    def __init__(self, workload_name=None, workload_id=None, display_name=None, platform=None):

        self._workload_name = None
        self._workload_id = None
        self._display_name = None
        self._platform = None

        if workload_name is not None:
            self._workload_name = workload_name
        if workload_id is not None:
            self._workload_id = workload_id
        if display_name is not None:
            self._display_name = display_name
        if platform is not None:
            self._platform = platform
    
    def to_dict(self):
         """Returns the model properties as a dict"""
         result = {}
         result["workload_name"] = self._workload_name
         result["workload_id"] = self._workload_id
         result["display_name"] = self._display_name
         result["platform"] = self._platform
         return result

         
    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

def pushMsgToTeams(data,HOOK_URL):
    
    message = {
      "@context": "https://schema.org/extensions",
      "@type": "MessageCard",
      "themeColor": data["colour"],
      "title": data["title"],
      "text": data["text"]
    }

    req = Request(HOOK_URL, json.dumps(message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        print("Message posted")
        return { "status": "200 OK"}
    except HTTPError as e:
        print("Request failed: %d %s" % ( e.code, e.reason))
    except URLError as e:
        print("Server connection failed: %s" % (e.reason))

def lambda_handler(event, context):
    
    
    print("Event: " + str(event))

    message = {}

    for eventRecord in event['Records']:
        message = ast.literal_eval(eventRecord['Sns']['Message'])
        
    HOOK_URL = os.environ['MS_TEAMS_WEB_HOOK_URL']
    status = message['status']
    workload_id = message['workload_id']
    quantine_period_seconds = message['quantine_period_seconds']
    
    lambda_response_code = message['lambda_response_code']

    if(lambda_response_code == 425):
        print("Ignoring duplicate request to isolate workload %d, already in quarantine state" % (workload_id))
        return
    elif(lambda_response_code == 500):
        data = {
            "colour": "d63333", # Red
            "title": "%s Failure Alert : %s" % (status,workload_id),
            "text": "[URGENT] Attempt to %s infected workload %d has failed, recommend immediate action to be taken" % (status,workload_id)
        }
        pushMsgToTeams(data, HOOK_URL)
    else:
        workload_name = message['workload_name']
        display_name = message['display_name']
        platform = message['platform']
        workloadData = WorkloadInfo(workload_name,workload_id,display_name,platform)

        if status.lower() == 'quarantine':
            auto_release_quarantine = message['auto_release_quarantine']
            colour = "ffff00" # Yellow
            text = "Workload %d has been quarantined using firewall rules for a period of %s seconds" % (workloadData._workload_id, quantine_period_seconds)
            if(auto_release_quarantine==0):
                text = "Workload %d has been quarantined using firewall rules for an indefinite period" % (workloadData._workload_id)
                colour = "ffa500" # Orange
            data = {
                "colour": colour,
                "title": "Quarantine Alert : %s" % workloadData.to_dict(),
                "text": text
            }
        elif status.lower() == 'released':
            data = {
                "colour": "64a837", # Green
                "title": "Release Alert : %s" % workloadData.to_dict(),
                "text": "Workload %d has been released from quarantine after a period of %s seconds " % (workloadData._workload_id, quantine_period_seconds)
            }
        
        pushMsgToTeams(data, HOOK_URL)
    
    
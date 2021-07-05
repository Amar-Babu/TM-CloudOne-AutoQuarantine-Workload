from __future__ import print_function
import json
import ast 
import os
import sys, warnings
import deepsecurity
import time
from deepsecurity.rest import ApiException
from deepsecurity.models.firewall_computer_extension import FirewallComputerExtension
from pprint import pprint

import boto3
from botocore.exceptions import ClientError

# Version
api_version = 'v1'

def get_secret(key, region_name = 'us-east-1'):
    secret_name = key
    region_name = region_name

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        return get_secret_value_response['SecretString']
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            print("The requested secret can't be decrypted using the provided KMS key:", e)
        elif e.response['Error']['Code'] == 'InternalServiceError':
            print("An error occurred on service side:", e)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            text_secret_data = get_secret_value_response['SecretString']
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']


#Methods
# Get the firewall isolation ruleIDs, create if not already found in the system
def getFirstFirewallRuleIDWithNameValue(FirewallRulesApi,string_value):

    firewallPolicySearch = deepsecurity.SearchCriteria(field_name = 'name',string_value = string_value)
    search_criteria_list = [firewallPolicySearch]
    fw_search_filter = deepsecurity.SearchFilter(search_criteria = search_criteria_list)
    fw_query_resultList = FirewallRulesApi.search_firewall_rules(api_version, search_filter=fw_search_filter).firewall_rules
    if len(fw_query_resultList) > 0 :
        return fw_query_resultList[0].id
    elif string_value == 'AntiMalwareIsolate-Block-All-Outgoing-L3':
        print('Firewall rule '+ string_value + ' not found, creating a new L3 rule')
        fw_blockAllOutgoing = deepsecurity.FirewallRule(action = 'deny', alert_enabled = False,  any_flags = True,description= 'Block all outgoing traffic L3', destination_ip_not = False ,destination_ip_type ='any',destination_mac_not = False, destination_mac_type = 'any',destination_port_not = False,destination_port_type = 'any',direction = 'outgoing',frame_not= False,frame_number = 0,frame_type = 'any',include_packet_data = False,log_disabled = False, name= 'AntiMalwareIsolate-Block-All-Outgoing-L3',  priority = '3', protocol = 'any',protocol_not =False,source_ip_not = False,source_ip_type ='any',source_mac_not= False,source_mac_type='any',source_port_not=False,source_port_type='any')    
        api_response = FirewallRulesApi.create_firewall_rule(fw_blockAllOutgoing, api_version)
        return api_response.id
    else:
        print('Firewall rule '+ string_value + ' not found, creating a new L3 rule')
        fw_blockAllIncoming = deepsecurity.FirewallRule(action = 'deny', alert_enabled = False,  any_flags = True,description= 'Block all incoming traffic L3', destination_ip_not = False ,destination_ip_type ='any',destination_mac_not = False, destination_mac_type = 'any',destination_port_not = False,destination_port_type = 'any',direction = 'incoming',frame_not= False,frame_number = 0,frame_type = 'any',include_packet_data = False,log_disabled = False, name= 'AntiMalwareIsolate-Block-All-Incoming-L3',  priority = '3', protocol = 'any',protocol_not =False,source_ip_not = False,source_ip_type ='any',source_mac_not= False,source_mac_type='any',source_port_not=False,source_port_type='any')    
        api_response = FirewallRulesApi.create_firewall_rule(fw_blockAllIncoming, api_version)
        return api_response.id
    return 0

def getPreviousEpochTime(timeBufferInMins):
    previousEpochTimeInMillisecs = int((time.time() - 60*timeBufferInMins)*1000)
    return previousEpochTimeInMillisecs

def getValidComputerID(ComputersApi):
    expand_options = deepsecurity.Expand()
    expand_options.add(expand_options.none)
    expand = expand_options.list()
    overrides = False
    api_response = ComputersApi.search_computers(api_version, search_filter=deepsecurity.SearchFilter(), expand=expand, overrides=overrides)
    return api_response.computers[-1].id

# Get the scheduledTask ID, create if not already found in the system
def getFirstScheduledTaskWithNameValue(string_value,ScheduledTasksApi,ComputersApi):
    scheduledTaskSearch = deepsecurity.SearchCriteria(field_name = 'name',string_value = string_value)
    search_criteria_list = [scheduledTaskSearch]
    search_filter = deepsecurity.SearchFilter(search_criteria = search_criteria_list)
    st_query_resultList = ScheduledTasksApi.search_scheduled_tasks(api_version, search_filter=search_filter).scheduled_tasks
    if len(st_query_resultList) > 0 :
        return st_query_resultList[0]
    elif 'Custom-ScheduledTask-SendPolicy-Now-' in string_value:
        print('Scheduled task '+ string_value + ' not found, creating a new task')
        computerFilter = deepsecurity.ComputerFilter(type='computer',computer_id = getValidComputerID(ComputersApi))
        sendPolicyTaskParameters = deepsecurity.SendPolicyTaskParameters(computer_filter = computerFilter)
        onceOnlyScheduleParameters = deepsecurity.OnceOnlyScheduleParameters(start_time=getPreviousEpochTime(10))
        scheduleDetails = deepsecurity.ScheduleDetails(recurrence_type= 'none', time_zone = 'US/Eastern',once_only_schedule_parameters = onceOnlyScheduleParameters)
        scheduled_task = deepsecurity.ScheduledTask(name=string_value, enabled = False, send_policy_task_parameters= sendPolicyTaskParameters,type = 'send-policy',schedule_details = scheduleDetails)
        api_response = ScheduledTasksApi.create_scheduled_task(scheduled_task, api_version)
        return api_response
    return 0

def pushPolicyToComputer(computer_id,ScheduledTasksApi,ComputersApi):
    refreshPolicySchedTaskName= 'Custom-ScheduledTask-SendPolicy-Now-' + str(computer_id)
    refreshPolicySchedTask = getFirstScheduledTaskWithNameValue(refreshPolicySchedTaskName,ScheduledTasksApi,ComputersApi)
    refreshPolicySchedTask._enabled = True
    refreshPolicySchedTask._run_now = True
    refreshPolicySchedTask._send_policy_task_parameters._computer_filter._computer_id = computer_id
    response = ScheduledTasksApi.modify_scheduled_task(refreshPolicySchedTask._id, refreshPolicySchedTask, api_version)
    print("Policy settings pushed to ", computer_id)
    return 

def lambda_handler(event, context):
    
    print("Disable Isolate Event :  : ",event)

    host_id = event[os.environ['HOST_ID_KEY']]

    ApiSecretKey = os.environ['APIKEY']
    regionName = os.environ['SECRETMANAGER_REGION_NAME']
    
    print("APISecretKey used : ",ApiSecretKey)

    firewallConfigDict = event['IsolateLambdaResult']['Payload']['body']['original_firewall_config']
    print("Firewall ConfigObtained  : ",firewallConfigDict)

    # Setup
    if not sys.warnoptions:
        warnings.simplefilter("ignore")
    configuration = deepsecurity.Configuration()
    configuration.host = 'https://cloudone.trendmicro.com/api'

    # Authentication
    configuration.api_key['api-secret-key'] = get_secret(key = ApiSecretKey,region_name = regionName)


    # Initialization
    # Set Any Required Values
    FirewallRulesApi = deepsecurity.FirewallRulesApi(deepsecurity.ApiClient(configuration))
    ComputerFirewallRuleAssignmentsApi = deepsecurity.ComputerFirewallRuleAssignmentsApi(deepsecurity.ApiClient(configuration))
    ComputersApi = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
    ScheduledTasksApi = deepsecurity.ScheduledTasksApi(deepsecurity.ApiClient(configuration))

    cm_search_filter = deepsecurity.SearchFilter()
    expand_options = deepsecurity.Expand()
    expand_options.add(expand_options.none)
    expand = expand_options.list()
    overrides = False

    #MainLogic
    try:

        reconstitutedOrigianlFirewallConfig = FirewallComputerExtension( state=firewallConfigDict['state'], global_stateful_configuration_id=firewallConfigDict['global_stateful_configuration_id'], stateful_configuration_assignments=None, rule_ids= firewallConfigDict['rule_ids'])
        print('reconstitutedOrigianlFirewallConfig : ' + str(reconstitutedOrigianlFirewallConfig))
       
        # Modify a computer
        print("Resetting firewall rules to original configuration for ", host_id)
        expand_options = deepsecurity.Expand()
        expand_options.add(expand_options.firewall)
        expand = expand_options.list()
        computer = deepsecurity.Computer(firewall=reconstitutedOrigianlFirewallConfig)
        api_response = ComputersApi.modify_computer(host_id, computer, api_version, expand=expand, overrides=True)
        #pprint(api_response)
        pushPolicyToComputer(host_id,ScheduledTasksApi,ComputersApi)
        print("Firewall rules reset for ", host_id)

        '''
        # Optional Read to verify that firewall isolation rules have been reset
        # Describe the computer after change
        expand_options = deepsecurity.Expand()
        expand_options.add(expand_options.firewall)
        expand = expand_options.list()
        computer = ComputersApi.describe_computer(host_id, api_version, expand=expand, overrides=overrides)
        firewall = computer._firewall
        pprint(firewall)
        '''
        
        print('Completed release of quarantine for ',host_id)
        
        return {
        'statusCode': 200,
        'body': json.dumps('Completed release of quarantine !')
        }
        
        
    except ApiException as e:
        print("An exception occurred when calling API : %s\n" % e)
    return {
        'statusCode': 400,
        'body': json.dumps('Error during release of quarantine !')
    }



    


    
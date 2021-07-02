import json
import os
import ast 
import boto3

def triggerStepFunction(stateMachineArn,customInput,region_name = 'us-east-1',):
    stepFunction = boto3.client('stepfunctions',region_name=region_name)
    response = stepFunction.start_execution(
        stateMachineArn=stateMachineArn,
        input = json.dumps(customInput)
    )
    return 

def lambda_handler(event, context):
    
    quarantine_period_in_secs = int(os.environ['QUARANTINE_PERIOD_IN_SECS_INT'])
    stateMachineArn = os.environ['TM_AUTOISOLATE_WORKLOAD_STATE_MACHINE_ARN']
    regionName = os.environ['STEP_FUNCTION_REGION_NAME']
    autoReleaseQuarantineBinaryFlag = int(os.environ['AUTO_RELEASE_QUARANTINE_BINARY_FLAG'])
    
    HostIDList = []
    for eventRecord in event['Records']:
        for message in ast.literal_eval(eventRecord['Sns']['Message']):
            HostIDList.append(message['HostID'])

    # Remove Duplicate Entries
    HostIDList = list(dict.fromkeys(HostIDList))    

    print("HostIDList :",HostIDList)
    
    # Target Host to Isolate / Event is generated for each AntiMalware Alert which corresponds to a single compute instance
    host_id = HostIDList[0]

    customInput = {
            'HOST_ID': host_id,
            'QUARANTINE_PERIOD_IN_SECS': quarantine_period_in_secs,
            'AUTO_RELEASE_QUARANTINE_BINARY_FLAG' : autoReleaseQuarantineBinaryFlag,
            'IsolateLambdaResult': {
                'Payload': {
                    'statusCode': 400,
                    'body': {
                        'computer_display_name': "placeholder",
                        'computer_host_name': "placeholder",
                        'computer_platform': "placeholder"
                            }
                    }
                        
            },
            'ReleaseLambdaResult': {
                'Payload': {
                    'statusCode': 400,
                    'body': "placeholder"
                    }
                        
            }
        }
    
    triggerStepFunction(stateMachineArn,customInput,regionName)
    
    return {
        'statusCode': 200,
        'body': json.dumps('Successfully triggered TM-AutoIsolate-Workload-State-Machine !')
    }

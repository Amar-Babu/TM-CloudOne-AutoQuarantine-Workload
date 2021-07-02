# TM-CloudOne-AutoQuarantine-Workload

##  Overview  
Enabling automated quarantine of malware infected workloads is a critical capability that safeguards workloads without the need of manual intervention.

![image](https://user-images.githubusercontent.com/22888429/124211767-8bcda780-daa2-11eb-8d3a-fe6158a4ecce.png)

## TM-AutoIsolate-Workload-State-Machine
![image](https://user-images.githubusercontent.com/22888429/124212475-ddc2fd00-daa3-11eb-8903-02b42597c5de.png)

## TM-Workload-Quarantine-Cycle-Trigger-StepFunction-Lambda
Add the following environment variables under configuration tab
| KEY  | VALUE | OPTIONS | 
| ---  | ----- | ------- | 
| AUTO_RELEASE_QUARANTINE_BINARY_FLAG  | 1  | 0 - For Indefinite Quarantine / 1 - Timed release of workload | 
| QUARANTINE_PERIOD_IN_SECS_INT  | 180  | Any valid whole number, ensure its below Max threshold for delay period supported in AWS Step function |
| STEP_FUNCTION_REGION_NAME	| us-east-1 | Any valid AWS region | 
| TM_AUTOISOLATE_WORKLOAD_STATE_MACHINE_ARN	| arn:aws:states:us-east-1:XXXXXXXXXXXX:stateMachine:TM-AutoIsolate-Workload-State-Machine | |

## TM-Workload-Quarantine-Status-Teams-Publisher-Lambda
Add the following environment variables under configuration tab
| KEY  | VALUE |
| ---  | ----- |
| MS_TEAMS_WEB_HOOK_URL | https://someorg.webhook.office.com/webhookb2/validurl |

![image](https://user-images.githubusercontent.com/22888429/124214355-ecf77a00-daa6-11eb-915a-e3d7ab9015a3.png)
![image](https://user-images.githubusercontent.com/22888429/124214372-f4b71e80-daa6-11eb-9c42-228818d1cce1.png)
![image](https://user-images.githubusercontent.com/22888429/124214398-fe408680-daa6-11eb-9e08-528f89c33673.png)

## TM-Workload-Impose-Quarantine-Lambda
Add the following environment variables under configuration tab
| KEY  | VALUE |
| ---  | ----- |
| APIKEY	| API-KEY-STORED-IN-AWS-SECRET-STORE | 
| HOST_ID_KEY	| HOST_ID |
| SECRETMANAGER_REGION_NAME |	us-east-1 |

## TM-Workload-Release-Quarantine-Lambda
Add the following environment variables under configuration tab
| KEY  | VALUE |
| ---  | ----- |
| APIKEY	| API-KEY-STORED-IN-AWS-SECRET-STORE | 
| HOST_ID_KEY	| HOST_ID |
| SECRETMANAGER_REGION_NAME |	us-east-1 |
 

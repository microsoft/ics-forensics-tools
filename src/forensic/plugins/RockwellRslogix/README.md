
## SUPPORTED SCENARIOS
- Tasks usage
- Project Metadata
- Call Graph

### Analyzers arguments:
#### RockwellRslogixBlockLogic
| **args**              | **Description**							                    | **Must / Optional** |
|-----------------------|-------------------------------------------|---------------------|
| `--logic_all`					          | Execute all logic options	 | optional            |
| `--logic_project_info`					 | Execute project info logic    | optional            |
| `--logic_tasks`						       | Execute tasks logic        | optional            |

#### RockwellRslogixOnlineOfflineCompare
| **args**            | **Description**							                    | **Must / Optional** |
|---------------------|-------------------------------------------|---------------------|
| `--compare_ip`					 | PLC IP to be compared					 | must                |
| `--project_file`	   | Path to the project (ACD file)	           | must                |

### Execute the following commands in this order
	 python driver.py -s -v RockwellRslogix --ip ips.csv
     python driver.py -s -v RockwellRslogix --ip ips.csv --analyzer RockwellRslogixRawFileParser
     python driver.py -s -v RockwellRslogix --ip ips.csv --analyzer RockwellRslogixBlockLogic --logic_all
     (Optional) python driver.py -s -v RockwellRslogix --ip ips.csv --analyzer RockwellRslogixOnlineOfflineCompare --compare_ip <plc_ip> --project_file <ACD project file path>

#### PLC authentication
Authentication with username and password is not supported.

### Output:
Depending on the model you choose to investigate, the data presented per model.
- The uploaded PLC project with parsed metadata
- Project Metadata and uniqueness
<br>![project_info.png](../../../../assets/images/rockwell_rslogix/project_info.png)
- Call graph - program connection based execution graph
<br>![call_graph.png](../../../../assets/images/rockwell_rslogix/call_graph.png)
- Tasks usage
<br>![tasks_info.png](../../../../assets/images/rockwell_rslogix/tasks_info.png)
- Online <-> Offline Block Comparison
<br>![offline_online_compare.png](../../../../assets/images/rockwell_rslogix/offline_online_compare.png)

## Resources and Technical data & solution:
[Microsoft Defender for IoT](https://azure.microsoft.com/en-us/services/iot-defender/#overview) is an agentless network-layer security solution that allows
organizations to continuously monitor and discover assets, detect threats, and manage vulnerabilities in their IoT/OT
and Industrial Control Systems (ICS) devices, on-premises and in Azure-connected environments.

[Section 52 under MSRC blog](https://msrc-blog.microsoft.com/?s=section+52)    <br/>
[ICS Lecture given about the tool](https://ics2022.sched.com/event/15DB2/deep-dive-into-plc-ladder-logic-forensics)    <br/>
[Section 52 - Investigating Malicious Ladder Logic | Microsoft Defender for IoT Webinar - YouTube](https://www.youtube.com/watch?v=g3KLq_IHId4&ab_channel=MicrosoftSecurityCommunity)

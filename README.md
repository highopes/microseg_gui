# microseg_gui

## Description

This is not just a GUI version of microseg. It comes with a whole new set of features and usage methods. This application helps to build a zero-trust environment that micro-segments an existing EPG of an ACI. The segmentation is based on analytics from  AppDynamics. The endpoints may or may not be virtual machines. It works well in multi-hypervisor or BM/VM hybrid environment. The micorseg_gui can automatically deal with it. If endpoints all have their own AppDynamics' agents, all will be automatically done. If not, two JSON files can help to manually deal with the application tiers/hosts mapping and EPG relationships. 

## Installation

The microseg_gui dosen't need to install. It's a python script directly running in your python environment.

## Environment

Required <br>
* Python 3.4+ <br>
* ACI and compatible ACI Cobra SDK (e.g. support microsegmentation feature of ACI) <br>
* All endpoints you want to deploy into sub-EPGs should be pre-configed in the same base EPG which associates to one Bridge Domain. It doesn’t care the number of subnets (EPs could belong to one or more subnets). <br>

Optional
* AppDynamics 4.3+ with Network Visibility Agents deployed

## Usage

Run the script with ‘python microseg_gui.py’ directly, a window will show (Integrated in ACI App Center is on the roadmap). Input the name of tenant, the application profile and the base EPG you want to be cut into mico-segments (or sub-EPGs). If the application is under AppDynamics(AppD)’s monitor, just give the name of the application in AppDynamics. If the application name omits, you will need JSON files for manual application definition. 
For example:
* ‘app_mapping.json’ for application tiers/hosts mapping
```json
{
  "Web": [
    "172.16.1.14",
    "172.16.1.15",
    "172.16.1.16"
  ],
  "App": [
    "172.16.1.24"
  ],
  "DB": [
    "172.16.1.34"
  ]
}
```
* ‘tier_relationship.json’ to build the application tiers relationships
```json
{
  "Web": {
    "app2web": [
      "consume"
    ]
  },
  "App": {
    "db2app": [
      "consume"
    ],
    "app2web": [
      "provide"
    ]
  },
  "DB": {
    "db2app": [
      "provide"
    ]
  }
}
```
Since the NetViz API of AppD doesn’t open,  the automatic extraction of the access relationships between application tiers is not supported currently. Please use JSON instead.

Currently the microseg_gui is used only for demo purpose. For productive usage, please contact the author at: weihang_hank@gmail.com

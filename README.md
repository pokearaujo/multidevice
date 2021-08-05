# Research about Multidevice

This repository does not require Selenium or any other browser to be interface with WhatsApp Web, it does so directly using a WebSocket.

## Requirements

In our tests this repository depends on node 16 or higher.

Node: `v16.x`

## ATTENTION: VS Dev:
* local storage has been replaced with dynamoDB. Before starting this, please do the [Local Development](#before-running-this-app) steps.

## Example

To run the example script, download or clone the repo and then type the following in terminal:

1. `cd multidevice`
2. `npm install`
3. `npm start`

## Debug

to debug the code, create a "launch.json" file inside the ".vscode" folder

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "command": "npm start",
            "name": "Run debugger",
            "request": "launch",
            "type": "node-terminal"
        }
    ]
}
```

Fork purpose:

Exploration of message decryption with session keys and re-playability

# Local Development

## Before running this app
1. start docker: `docker run --rm -d -p 8000:8000/tcp amazon/dynamodb-local:latest`
1. create dynamoDB table: `aws dynamodb create-table --key-schema AttributeName=client_number,KeyType=HASH --attribute-definitions AttributeName=client_number,AttributeType=S --provisioned-throughput ReadCapacityUnits=2,WriteCapacityUnits=2 --table-name wip_multi_device --endpoint-url http://localhost:8000`

To remove the table for testing, run the following then re-create it: `aws dynamodb describe-table --table-name wip_multi_device --endpoint-url http://localhost:8000`

## Docker for local dynamoDB
* start headless container: `docker run --rm -d -p 8000:8000/tcp amazon/dynamodb-local:latest`
* start container: `docker run --rm -p 8000:8000/tcp amazon/dynamodb-local:latest`
* see running containers: `docker ps -a`
* stop container: `docker stop <container ID>`


## Dynamo Snippets
aws cli snippets.
To get started, the table must exist. 
* create table: `
aws dynamodb create-table --key-schema AttributeName=client_number,KeyType=HASH --attribute-definitions AttributeName=client_number,AttributeType=S --provisioned-throughput ReadCapacityUnits=2,WriteCapacityUnits=2 --table-name wip_multi_device --endpoint-url http://localhost:8000
`
* create table with JSON: `aws dynamodb create-table --cli-input-json file://createLocalDynamoTable.json --endpoint-url http://localhost:8000`
* delete table: `
aws dynamodb delete-table --table-name wip_multi_device --endpoint-url http://localhost:8000
`
* decribe table:
`aws dynamodb describe-table --table-name wip_multi_device --endpoint-url http://localhost:8000`
* put item: `
aws dynamodb put-item --table-name wip_multi_device --item client_number=+447950964136, registrationId=199, advSecretKey=okN/xi3lmdFR4BEGJq5boaZ84FBQSwkgEW8nRtbw6d4= --endpoint-url http://localhost:8000
`
* put item: `
aws dynamodb put-item --table-name wip_multi_device --item file://putItem.json --endpoint-url http://localhost:8000
`
* query table: `
aws dynamodb query --table-name wip_multi_device --key-condition-expression "client_number=:cliNo" --expression-attribute-values '{":cliNo":{"S":"+447467917138"}}' --endpoint-url http://localhost:8000
`
* get item: (doesn't work)
`
aws dynamodb get-item --table-name wip_multi_device --key '{"client_number": {"S": "+447950964136"}' --endpoint-url http://localhost:8000
`
* scan (get all data):
`aws dynamodb scan  --table-name wip_multi_device --endpoint-url http://localhost:8000`

# Research about Multidevice

This repository does not require Selenium or any other browser to be interface with WhatsApp Web, it does so directly using a WebSocket.

## Requirements

In our tests this repository depends on node 16 or higher.

Node: `v16.x`

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

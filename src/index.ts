import { WaClient } from './client';
import { writeFileSync, existsSync, mkdirSync, readFile, readFileSync } from 'fs';
import mimeTypes from 'mime-types';
import { MessageType } from './utils/Utils';
import got from 'got';

(async () => {
    /** first client */
    const session = new WaClient({
        sessionName: 'bot-03',
        onSocketClose: (e) => {
            console.error(e);
        },
        log: true,
    });

    console.log('open connection');
    await session.createConnection();

    session.on('open', (me) => {
        console.log('open connection', me);
    });

    session.on('qr', (qr: string) => {
        console.log('received qr', qr);
    });

    session.on('history-sync', (history) => {
        console.log('history sync ', history);
    });

    session.on('group-update', (update: any) => {
        console.log('received group update', update);
    });

    session.on('close', (update: any) => {
        console.log('connection was closed', update);
    });

    session.on('message', async (message: any) => {
        console.log('message received', message);

        const messageType = session.getMessageType(message);

        const msgContent = message.deviceSentMessage?.message ?? message; 
        let mediaBuffer = null;
        if (session.isMedia(msgContent)) {
            mediaBuffer = (await session.downloadMedia(msgContent)) as Buffer;
            if (!existsSync('./files')) {
                mkdirSync('./files');
            }

            writeFileSync(`./files/${message.externalId}.${mimeTypes.extension(msgContent[messageType].mimetype) ?? ''}`, mediaBuffer, {
                flag: 'w',
            });
        }

        const conversation = msgContent?.conversation ?? msgContent[messageType]?.caption ?? null;

        if (!conversation) {
            return;
        }

        if (conversation == '!ping') {
            await session.sendMessage(message.chat, 'pong', MessageType.text);

            return;
        }

        if (conversation.startsWith('!creategroup')) {
            if (message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command in group not allowned', MessageType.text);

                return;
            }

            const params = conversation.split(' ');
            params.shift();

            const name = params.length > 0 ? params.join(' ') : null;
            if (!name) {
                await session.sendMessage(message.chat, 'Invalid group name', MessageType.text);

                return;
            }

            const user = message.chat.getUser();

            await session.sendMessage(message.chat, `Creating group *${name}* with: ${user}`, MessageType.text);

            const result = await session.createGroup(name, [user]);

            console.log('created group', result.content);

            const id = result.content[0].attrs.id;
            await session.sendMessage(message.chat, `Group created with id: *${id}*`, MessageType.text);

            await session.addOrRemoveGroupAdmin(id, 'PROMOTE', [user]);

            return;
        }

        if (conversation.startsWith('!changename')) {
            if (!message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command allowned only in group', MessageType.text);

                return;
            }

            const id = message.chat.getUser();

            const params = conversation.split(' ');
            params.shift();

            const name = params.length > 0 ? params.join(' ') : null;
            if (!name) {
                await session.sendMessage(message.chat, 'Invalid group name', MessageType.text);

                return;
            }

            await session.setGroupName(id, name);

            await session.sendMessage(message.chat, `Group name has changed to *${name}*`, MessageType.text);
        }

        if (conversation.startsWith('!changedesc')) {
            if (!message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command allowned only in group', MessageType.text);

                return;
            }

            const id = message.chat.getUser();

            const params = conversation.split(' ');
            params.shift();

            const desc = params.length > 0 ? params.join(' ') : '';

            await session.setGroupDescription(id, desc);

            await session.sendMessage(message.chat, `Group description has changed to: ${desc}`, MessageType.text);
        }

        if (conversation.startsWith('!invite')) {
            if (!message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command allowned only in group', MessageType.text);

                return;
            }

            const id = message.chat.getUser();

            const code = await session.getGroupInvitationCode(id);

            await session.sendMessage(message.chat, `Group invite code: ${code}`, MessageType.text);
        }

        if (conversation.startsWith('!info')) {
            if (!message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command allowned only in group', MessageType.text);

                return;
            }

            const id = message.chat.getUser();

            const info = await session.getGroupInfo(id);

            console.log('info');
            console.dir(info, { depth: null });
        }

        if (conversation.startsWith('!contactinfo')) {
            if (message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command not allowned in group', MessageType.text);

                return;
            }

            const info = await session.getContactInfo([message.chat]);

            console.log('info');
            console.dir(info, { depth: null });
        }

        if (conversation.startsWith('!add')) {
            if (!message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command allowned only in group', MessageType.text);

                return;
            }

            const id = message.chat.getUser();

            const params = conversation.split(' ');
            params.shift();

            await session.addOrRemoveGroupParticipants(id, 'ADD', params);

            await session.sendMessage(message.chat, `Group participants added *${params.join(',')}*`, MessageType.text);
        }

        if (conversation.startsWith('!remove')) {
            if (!message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command allowned only in group', MessageType.text);

                return;
            }

            const id = message.chat.getUser();

            const params = conversation.split(' ');
            params.shift();

            await session.addOrRemoveGroupParticipants(id, 'REMOVE', params);

            await session.sendMessage(message.chat, `Group participants removed *${params.join(',')}*`, MessageType.text);
        }

        if (conversation.startsWith('!promote')) {
            if (!message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command allowned only in group', MessageType.text);

                return;
            }

            const id = message.chat.getUser();

            const params = conversation.split(' ');
            params.shift();

            await session.addOrRemoveGroupAdmin(id, 'PROMOTE', params);

            await session.sendMessage(message.chat, `Group participants promoted to admin *${params.join(',')}*`, MessageType.text);
        }

        if (conversation.startsWith('!demote')) {
            if (!message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command allowned only in group', MessageType.text);

                return;
            }

            const id = message.chat.getUser();

            const params = conversation.split(' ');
            params.shift();

            await session.addOrRemoveGroupAdmin(id, 'DEMOTE', params);

            await session.sendMessage(message.chat, `Group participants promoted to user *${params.join(',')}*`, MessageType.text);
        }

        if (conversation.startsWith('!changeurlpic')) {
            if (!message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command allowned only in group', MessageType.text);

                return;
            }

            const id = message.chat.getUser();

            const params = conversation.split(' ');
            const url = params[1] ?? null;
            if (!url) {
                await session.sendMessage(message.chat, `Invalid url`, MessageType.text);

                return;
            }

            const buffer = await got.get(url, { responseType: 'buffer' });
            await session.setGroupImage(id, buffer.body);

            await session.sendMessage(message.chat, `Group image has changed`, MessageType.text);
        }

        if (conversation.startsWith('!changepic')) {
            if (!message.chat.isGroup()) {
                await session.sendMessage(message.chat, 'Command allowned only in group', MessageType.text);

                return;
            }

            const id = message.chat.getUser();

            if (messageType != MessageType.image) {
                await session.sendMessage(message.chat, 'Needs to send a image', MessageType.text);

                return;
            }

            await session.setGroupImage(id, mediaBuffer);

            await session.sendMessage(message.chat, 'Group image has changed', MessageType.text);
        }

        if (conversation.startsWith('!imageurl')) {
            const params = conversation.split(' ');
            const url = params[1] ?? null;
            if (!url) {
                await session.sendMessage(message.chat, `Invalid url`, MessageType.text);

                return;
            }

            await session.sendMessage(message.chat, { url }, MessageType.image);
        }

        if (conversation.startsWith('!exists')) {
            const params = conversation.split(' ');
            const number = params[1] ?? null;
            if (!number) {
                await session.sendMessage(message.chat, `Invalid phone number`, MessageType.text);

                return;
            }

            const result = await session.isOnWhatsApp(number);

            await session.sendMessage(message.chat, `Number exists: *${result.exists ? 'true' : 'false'}*\nNumber: *${result.jid ? result.jid : 'N/A'}*`, MessageType.text);
        }

        if (conversation.startsWith('!close')) {
            await session.sendMessage(message.chat, 'Closing session', MessageType.text);

            session.destroy();
        }

        if (conversation.startsWith('!testid')) {
            const msg = await session.sendMessage(message.chat, 'Testing message id', MessageType.text);

            await session.sendMessage(message.chat, `Last message id: *${msg.id}*`, MessageType.text);
        }

        if (conversation == '!buttons') {
            await session.sendMessage(
                message.chat,
                {
                    headerType: 1,
                    contentText: 'Hello',
                    footerText: 'Hi',
                    buttons: [
                        {
                            buttonId: '1',
                            buttonText: {
                                displayText: 'Yes',
                            },
                            type: 1,
                        },
                        {
                            buttonId: '2',
                            buttonText: {
                                displayText: 'No',
                            },
                            type: 1,
                        },
                    ],
                },
                MessageType.buttonsMessage,
            );
        }

        if (conversation == '!buttonsurl') {
            const buttons = [
                {
                    label: 'Google',
                    url: 'https://google.com',
                },
                {
                    label: 'Facebook',
                    url: 'https://facebook.com',
                },
            ];

            await session.sendMessage(
                message.chat,
                {
                    hydratedTemplate: {
                        hydratedContentText: 'Test',
                        hydratedButtons: buttons.map((button, i) => {
                            return {
                                index: i,
                                urlButton: {
                                    displayText: button.label,
                                    url: button.url,
                                },
                            };
                        }),
                    },
                },
                MessageType.templateMessage,
            );
        }

        if (conversation == '!list') {
            const rows = [
                { title: 'Row 1', description: "Hello it's description 1", rowId: 'rowid1' },
                { title: 'Row 2', description: "Hello it's description 2", rowId: 'rowid2' },
            ];

            const sections = [{ title: 'Section 1', rows: rows }];
            const button = {
                buttonText: 'Click Me!',
                description: "Hello it's list message",
                sections: sections,
            };

            await session.sendMessage(message.chat, button, MessageType.listMessage);
        }

        if (conversation == '!sendimage') {
            await session.sendMessage(message.chat, { url: 'https://avatars.githubusercontent.com/u/13368319?v=4' }, MessageType.image);
        }
    });

    /** second client */
    // const session2 = new WaClient({
    //     sessionName: 'bot-04',
    //     onSocketClose: (e) => {
    //         console.error(e)
    //     }
    // })
    // await session2.createConnection()
})();

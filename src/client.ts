import {
    randomBytes,
    areBuffersEqual,
    HEADER,
    CERT_ISSUER,
    BIG_ENDIAN_CONTENT,
    KEY_BUNDLE_TYPE,
    xmppPreKey,
    xmppSignedPreKey,
    writeRandomPadMax16,
    phashV2,
    generateMessageID,
    isGroupID,
    downloadAndDecrypt,
    USER_JID_SUFFIX,
    wapBytes,
    MessageType,
    encryptedStream,
    generateThumbnail,
    getAudioDuration,
    DEFAULT_ORIGIN,
    unixTimestampSeconds,
} from './utils/Utils';
import { Socket } from './socket/Socket';
import { FrameSocket } from './socket/FrameSocket';
import { NoiseHandshake } from './socket/NoiseHandshake';
import { toLowerCaseHex, randomHex } from './utils/HexHelper';

import { generatePayloadRegister } from './payloads/RegisterPayload';
import { Binary } from './proto/Binary';
import { encodeStanza, generateId, decodeStanza, unpackStanza } from './proto/Stanza';
import { generateIdentityKeyPair, generateRegistrationId, generateSignedPreKey, KeyPair, sharedKey, SignedKeyPair } from './utils/Curve';
import { WapNode } from './proto/WapNode';
import { encodeB64 } from './utils/Base64';
import { G_US, S_WHATSAPP_NET, toUserId, WapJid } from './proto/WapJid';
import { generatePayloadLogin } from './payloads/LoginPayload';
import { proto as WAProto } from '../WAMessage/WAMessage';

import { StorageService } from './services/StorageService';
import { NoiseSocket } from './socket/NoiseSocket';
import { StorageSignal } from './signal/StorageSignal';
import { WaSignal } from './signal/Signal';
import { Wid } from './proto/Wid';

import { deviceParser, e2eSessionParser } from './proto/ProtoParsers';

import { EventEmitter } from 'stream';
import { EventHandlerService } from './services/EventHandlerService';
import { IMediaConn } from './interfaces/IMediaConn';
import { inflate } from 'zlib';
import { WAMediaUpload, WATextMessage, MessageOptions, WAMessageType, WAMessageContent, MimetypeMap, Mimetype, MessageTypeProto, MediaPathMap } from './utils/Constants';
import { createReadStream, writeFileSync } from 'fs';
import got, { Method } from 'got';
import { Agent } from 'https';
import { promises as fs } from 'fs';
import sharp from 'sharp';
import { IWAGroupMetadata } from './interfaces/IWAGroupMetadata';

const sessions = {};

interface Props {
    sessionName: string;
    log?: boolean;
    initialStorageData?: any;
    writeFileStorage?: boolean;
    /**
     * @description Callback stops when socket is closed
     */
    onSocketClose(err: Error): void;
}

export class WaClient extends EventEmitter {
    private KEEP_ALIVE_INTERVAL = 1e4 * Math.random() + 2e4;
    private keepAliveTimer: NodeJS.Timer;

    private eventHandler: EventHandlerService;
    private waSignal: WaSignal;
    private storageSignal: StorageSignal;
    private sessionName: string;
    private socket: Socket;
    private storageService: StorageService;
    private frame: FrameSocket;
    private noise: NoiseHandshake;
    private me: WapJid;
    private socketConn: NoiseSocket;
    private enableLog: boolean;

    private mediaConn: IMediaConn;

    private registrationId: number;

    /** keys */
    private ephemeralKeyPair: KeyPair;
    private signedIdentityKey: KeyPair;
    private noiseKey: KeyPair;
    private signedPreKey: SignedKeyPair;
    private advSecretKey: string;
    private socketWaitIqs = {};
    private decryptRetryCount = {};

    /** events */
    private onSocketClose: Function;

    private devices: Wid[];

    constructor({ sessionName, onSocketClose, log, initialStorageData, writeFileStorage }: Props) {
        super();

        if (sessions[sessionName]) {
            throw new Error(`SessionName "${sessionName}" already exists`);
        }

        sessions[sessionName] = this;
        this.sessionName = sessionName;
        this.onSocketClose = onSocketClose;
        this.enableLog = log ?? false;
        this.storageService = new StorageService('./sessions', initialStorageData, writeFileStorage ?? true);

        this.initConfig();
    }

    public log(...data: any[]) {
        if (!this.enableLog) {
            return;
        }

        console.log(...data);
    }

    private initConfig() {
        this.storageService.init(`${this.sessionName.replace(/ /g, '-')}.json`);
        this.storageSignal = new StorageSignal(this.storageService);
        this.waSignal = new WaSignal(this.storageService, this.storageSignal);
    }

    createConnection = () => {
        this.socket = new Socket();
        this.socket.open();
        this.ephemeralKeyPair = generateIdentityKeyPair();

        return new Promise((resolve, reject) => {
            this.socket.onOpen = async () => {
                try {
                    await this.handleSocketOpen();
                    resolve(true);
                } catch (err) {
                    reject(false);
                }
            };
        });
    };

    private handleSocketOpen = async () => {
        try {
            await this.configureConnection();
            this.createKeepAlive();
        } catch (e) {
            if (this.onSocketClose) {
                this.onSocketClose(e);
            }
        }
    };

    private configureConnection = async () => {
        this.frame = new FrameSocket(this.socket, HEADER);
        this.noise = new NoiseHandshake(this.frame);
        await this.noise.start('Noise_XX_25519_AESGCM_SHA256\0\0\0\0', HEADER);
        await this.noise.authenticate(this.ephemeralKeyPair.pubKey);

        const data = {
            clientHello: {
                ephemeral: this.ephemeralKeyPair.pubKey,
            },
        };

        const serverHelloEnc = await this.noise.sendAndReceive(WAProto.HandshakeMessage.encode(data).finish());

        this.log('received server hello', toLowerCaseHex(serverHelloEnc));
        const { serverHello } = WAProto.HandshakeMessage.decode(serverHelloEnc);
        if (!serverHello) {
            throw new Error('ServerHello payload error');
        }
        const { ephemeral: serverEphemeral, static: serverStaticCiphertext, payload: certificateCiphertext } = serverHello;
        if (serverEphemeral == null || serverStaticCiphertext == null || certificateCiphertext == null) {
            throw new Error('Missing server Ephemeral');
        }

        await this.noise.authenticate(serverEphemeral);
        await this.noise.mixIntoKey(sharedKey(serverEphemeral, this.ephemeralKeyPair.privKey));

        const staticDecoded = await this.noise.decrypt(serverStaticCiphertext);
        await this.noise.mixIntoKey(sharedKey(new Uint8Array(staticDecoded), this.ephemeralKeyPair.privKey));

        const certDecoded = await this.noise.decrypt(certificateCiphertext);
        const { details: certDetails, signature: certSignature } = WAProto.NoiseCertificate.decode(new Uint8Array(certDecoded));
        if (!certDetails || !certSignature) {
            throw new Error('certProto wrong');
        }

        const { issuer: certIssuer, key: certKey } = WAProto.Details.decode(certDetails);
        if (certIssuer != CERT_ISSUER || !certKey) {
            throw new Error('invalid issuer');
        }

        if (!areBuffersEqual(certKey, staticDecoded)) {
            throw new Error('cert key does not match issuer');
        }

        this.noiseKey = await this.storageService.getOrSave('noiseKey', () => generateIdentityKeyPair());

        const keyEnc = await this.noise.encrypt(new Uint8Array(this.noiseKey.pubKey));
        await this.noise.mixIntoKey(sharedKey(new Uint8Array(serverEphemeral), new Uint8Array(this.noiseKey.privKey)));

        this.signedIdentityKey = await this.storageService.getOrSave<KeyPair>('signedIdentityKey', () => generateIdentityKeyPair());
        this.signedPreKey = await this.storageService.getOrSave<SignedKeyPair>('signedPreKey', () => generateSignedPreKey(this.signedIdentityKey, 1));
        this.registrationId = await this.storageService.getOrSave<number>('registrationId', () => generateRegistrationId());

        this.me = this.storageService.get<WapJid>('me');

        const payload = !this.me ? generatePayloadRegister(this.registrationId, this.signedIdentityKey, this.signedPreKey) : generatePayloadLogin(this.me);
        const payloadEnc = await this.noise.encrypt(payload);

        this.noise.send(
            WAProto.HandshakeMessage.encode({
                clientFinish: {
                    static: new Uint8Array(keyEnc),
                    payload: new Uint8Array(payloadEnc),
                },
            }).finish(),
        );

        this.socketConn = await this.noise.finish();

        this.advSecretKey = await this.storageService.getOrSave<string>('advSecretKey', () => encodeB64(new Uint8Array(randomBytes(32))));

        this.eventHandler = new EventHandlerService(this.socketConn, this, this.storageService, this.waSignal);

        this.socketConn.onClose = this.onNoiseSocketClose.bind(this);
        this.socketConn.setOnFrame(this.onNoiseNewFrame.bind(this));
    };

    private onNoiseSocketClose = () => {
        this.emit('close', {
            reason: 'close',
        });

        this.destroyKeepAlive();
        if (this.onSocketClose) {
            this.onSocketClose();
        }
    };

    private sendMessageAndWait(stanza: WapNode): Promise<WapNode> {
        return new Promise((resolve, reject) => {
            this.socketWaitIqs[stanza.attrs.id] = {
                resolve,
                reject,
            };
            const frame = this.encodeStanza(stanza);
            this.socketConn.sendFrame(frame);
        });
    }

    onlySendFrame(stanza: WapNode) {
        const frame = this.encodeStanza(stanza);
        if (!this.socketConn) {
            throw 'No Socket Handler';
        }
        this.socketConn.sendFrame(frame);
    }

    public uploadPreKeys = async () => {
        const registrationId = this.storageService.get<number>('registrationId');
        const identityKey = this.storageService.get<KeyPair>('signedIdentityKey');
        const signedPreKey = this.storageService.get<SignedKeyPair>('signedPreKey');
        if (!identityKey || !signedPreKey) {
            this.log('invalid identityKey or signedPreKey from uploadPreKeys');
            return;
        }
        const preKeys = await this.waSignal.getOrGenPreKeys(30);
        if (preKeys.length == 0) {
            this.log('No preKey is available');
            return;
        }
        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                xmlns: 'encrypt',
                type: 'set',
                to: S_WHATSAPP_NET,
            },
            [
                new WapNode('registration', null, BIG_ENDIAN_CONTENT(registrationId)),
                new WapNode('type', null, KEY_BUNDLE_TYPE),
                new WapNode('identity', null, identityKey.pubKey),
                new WapNode('list', null, preKeys.map(xmppPreKey)),
                xmppSignedPreKey(signedPreKey),
            ],
        );
        const lastId = preKeys[preKeys.length - 1];
        this.socketConn.sendFrame(this.encodeStanza(stanza));
        await this.waSignal.markKeyAsUploaded(lastId.keyId);
        await this.waSignal.putServerHasPreKeys(true);
    };

    public sendPassiveIq = async (passive: boolean) => {
        const stanza = new WapNode(
            'iq',
            {
                to: S_WHATSAPP_NET,
                xmlns: 'passive',
                type: 'set',
                id: generateId(),
            },
            [new WapNode(passive ? 'passive' : 'active', null)],
        );

        return this.socketConn.sendFrame(this.encodeStanza(stanza));
    };

    public encodeStanza(node: any) {
        const enc =  encodeStanza(node);
        this.log(`TO SERVER (${enc.byteLength} bytes) ->`, node instanceof WapNode ? node.toString() : node);

        return enc;
    }

    public getMe() {
        return this.me;
    }

    public sendNotAuthozired(id: string) {
        return this.socketConn.sendFrame(
            this.encodeStanza(
                new WapNode(
                    'iq',
                    {
                        to: S_WHATSAPP_NET,
                        type: 'error',
                        id,
                    },
                    [
                        new WapNode('error', {
                            code: '401',
                            text: 'not-authorized',
                        }),
                    ],
                ),
            ),
        );
    }

    public getDevices() {
        return this.devices;
    }

    public setDevices(devices: Wid[]) {
        this.devices = devices;
    }

    public getNoiseKey() {
        return this.noiseKey;
    }

    public getRegistrationId() {
        return this.registrationId;
    }

    public getEphemeralKey() {
        return this.ephemeralKeyPair;
    }

    public getSignedIdentityKey() {
        return this.signedIdentityKey;
    }

    public getStorage() {
        return this.storageService;
    }

    public getSignedPreKey() {
        return this.signedPreKey;
    }

    public getAdvSecretKey() {
        return this.advSecretKey;
    }

    public async afterMessageDecrypt(node: WapNode) {
        const isGroup = !!node.attrs.participant;
        const isMe = isGroup ? node.attrs.participant.getUser() == this.me.getUser() : node.attrs.from.getUser() == this.me.getUser();
        this.sendMessageAck(node);
        isMe ? this.sendMessageSender(node) : this.sendMessageInactive(node);
    }

    public async sendMessageSender(node: WapNode) {
        const isGroup = !!node.attrs.participant;
        const stanza = new WapNode(
            'receipt',
            {
                type: 'sender',
                id: node.attrs.id,
                ...(isGroup ? { participant: node.attrs.participant } : { recipient: node.attrs.recipient }),
                to: node.attrs.from,
            },
            null,
        );
        this.onlySendFrame(stanza);
    }

    public async sendMessageInactive(node: WapNode) {
        const isGroup = !!node.attrs.participant;
        const isStatus = node.attrs.from.isStatusV3();
        const stanza = new WapNode(
            'receipt',
            {
                type: 'inactive',
                id: node.attrs.id,
                to: isStatus ? WapJid.create('status', 'broadcast', null) : node.attrs.from,
                ...(isGroup || isStatus
                    ? {
                          participant: node.attrs.participant,
                      }
                    : {}),
            },
            null,
        );
        this.onlySendFrame(stanza);
    }

    public async sendMessageAck(node: WapNode) {
        const isGroup = !!node.attrs.participant;
        const stanza = new WapNode(
            'ack',
            {
                class: 'receipt',
                id: node.attrs.id,
                to: isGroup ? node.attrs.from : WapJid.create(this.me.getUser(), 'c.us', null),
                ...(isGroup
                    ? {
                          participant: WapJid.createAD(this.me.getUser(), 0, 0, true),
                      }
                    : {}),
            },
            null,
        );
        this.onlySendFrame(stanza);
    }

    public async sendRetryReceipt(node: WapNode) {
        this.decryptRetryCount[node.attrs.id] = (this.decryptRetryCount[node.attrs.id] || 0) + 1;
        if (this.decryptRetryCount[node.attrs.id] >= 50) {
            delete this.decryptRetryCount[node.attrs.id];
            return;
        }
        const isGroup = !!node.attrs.participant;
        const registrationInfo = {
            registrationId: await this.storageSignal.getOurRegistrationId(),
            identityKeyPair: await this.storageSignal.getOurIdentity(),
        };

        const identityKey = this.signedIdentityKey;
        const signedPreKey = this.signedPreKey;
        const account = await this.storageService.get('account');
        const deviceIdentity = WAProto.ADVSignedDeviceIdentity.encode(account).finish();
        const key = await this.waSignal.getOrGenSinglePreKey();
        const count = this.decryptRetryCount[node.attrs.id] || 1;

        const receipt = new WapNode(
            'receipt',
            {
                id: node.attrs.id,
                type: 'retry',
                ...(node.attrs.recipient ? { recipient: node.attrs.recipient } : {}),
                ...(node.attrs.participant ? { participant: node.attrs.participant } : {}),
                to: isGroup ? node.attrs.from : WapJid.createAD(node.attrs.from._jid.user, 0, node.attrs.from._jid.device || 0, true),
            },
            [
                new WapNode(
                    'retry',
                    {
                        count: `${count}`,
                        id: node.attrs.id,
                        t: node.attrs.t,
                        v: '1',
                    },
                    null,
                ),
                new WapNode('registration', {}, BIG_ENDIAN_CONTENT(registrationInfo.registrationId)),
                ...(count > 1
                    ? [
                          new WapNode('keys', {}, [
                              new WapNode('type', {}, new Uint8Array([Buffer.from(this.waSignal.toSignalCurvePubKey(KEY_BUNDLE_TYPE))[0]])),
                              new WapNode('identity', {}, identityKey.pubKey),
                              xmppPreKey(key),
                              xmppSignedPreKey(signedPreKey),
                              new WapNode('device-identity', {}, new Uint8Array(deviceIdentity)),
                          ]),
                      ]
                    : []),
            ],
        );
        await this.sendMessageAndWait(receipt);
    }

    private handleStanza = async (stanza: WapNode) => {
        if (!(stanza instanceof WapNode)) {
            return null;
        }

        const tag = stanza.tag;
        //this.log('received tag node', tag);

        if (tag == 'xmlstreamend') {
            //this.socketConn.restart();
            return;
        }

        if (stanza.attrs && stanza.attrs.id && this.socketWaitIqs[stanza.attrs.id]) {
            this.socketWaitIqs[stanza.attrs.id].resolve(stanza);
            delete this.socketWaitIqs[stanza.attrs.id];
        }

        await this.eventHandler.handle(stanza);
    };

    private onNoiseNewFrame = async (frame) => {
        const data = await unpackStanza(frame);
        const stanza = decodeStanza(data);
        this.log('FROM SERVER ->', stanza.toString());
        await this.handleStanza(stanza);
    };

    public async ensureIdentityUser(user: WapJid, forceNewSession = false) {
        const sessionStorage = await this.waSignal.hasSession(user);
        if (!forceNewSession && sessionStorage) {
            return;
        }

        const userIdentity = new WapNode(
            'user',
            {
                jid: user,
                reason: 'identity',
            },
            null,
        );

        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                xmlns: 'encrypt',
                type: 'get',
                to: S_WHATSAPP_NET,
            },
            [new WapNode('key', {}, [userIdentity])],
        );

        const result = await this.sendMessageAndWait(stanza);
        const session = await e2eSessionParser(result, this.me);

        const device = {
            registrationId: session.regId,
            identityKey: Buffer.from(this.waSignal.toSignalCurvePubKey(session.identity)),
            signedPreKey: {
                keyId: session.skey.id,
                publicKey: Buffer.from(this.waSignal.toSignalCurvePubKey(session.skey.pubkey)),
                signature: session.skey.signature,
            },
            ...(session.key
                ? {
                      preKey: {
                          keyId: session.key.id,
                          publicKey: Buffer.from(this.waSignal.toSignalCurvePubKey(session.key.pubkey)),
                      },
                  }
                : {}),
        };

        await this.waSignal.createSignalSession(user, device);
    }

    public async sendMessage(id: string | WapJid, message: WAMessageType, type: MessageType, options: MessageOptions = {}) {
        const waMessage = await this.prepareMessage(message, type, options);
        const messageId = await this.sendMessageInternal(id, waMessage);

        return {
            id: messageId,
            message: waMessage,
        };
    }

    // baileys
    public async prepareMessage(message: WAMessageType, type: MessageType, options: MessageOptions = {}) {
        const content = await this.prepareMessageContent(message, type, options);

        const preparedMessage = this.prepareMessageFromContent(content, options);
        return preparedMessage;
    }

    // baileys
    public prepareMessageFromContent(message: WAMessageContent, options: MessageOptions) {
        if (!options.timestamp) options.timestamp = new Date(); // set timestamp to now
        if (typeof options.sendEphemeral === 'undefined') options.sendEphemeral = 'chat';
        // prevent an annoying bug (WA doesn't accept sending messages with '@c.us')
        //id = whatsappID (id)

        const key = Object.keys(message)[0];
        const timestamp = unixTimestampSeconds(options.timestamp);
        //const quoted = options.quoted

        if (options.contextInfo) message[key].contextInfo = options.contextInfo;

        /*if (quoted) {
            const participant = quoted.key.fromMe ? this.user.jid : (quoted.participant || quoted.key.participant || quoted.key.remoteJid)

            message[key].contextInfo = message[key].contextInfo || { }
            message[key].contextInfo.participant = participant
            message[key].contextInfo.stanzaId = quoted.key.id
            message[key].contextInfo.quotedMessage = quoted.message
            
            // if a participant is quoted, then it must be a group
            // hence, remoteJid of group must also be entered
            if (quoted.key.participant) {
                message[key].contextInfo.remoteJid = quoted.key.remoteJid
            }
        }*/

        if (options?.thumbnail) {
            message[key].jpegThumbnail = Buffer.from(options.thumbnail, 'base64');
        }

        /*const chat = this.chats.get(id)
        if (
            // if we want to send a disappearing message
            ((options?.sendEphemeral === 'chat' && chat?.ephemeral) || 
            options?.sendEphemeral === true) &&
            // and it's not a protocol message -- delete, toggle disappear message
            key !== 'protocolMessage' &&
            // already not converted to disappearing message
            key !== 'ephemeralMessage' 
        ) {
            message[key].contextInfo = {
                ...(message[key].contextInfo || {}),
                expiration: chat?.ephemeral || WA_DEFAULT_EPHEMERAL,
                ephemeralSettingTimestamp: chat?.eph_setting_ts
            }
            message = {
                ephemeralMessage: {
                    message
                }
            }
        } */

        message = WAProto.Message.fromObject(message);

        /*const messageJSON = {
            key: {
                remoteJid: id,
                fromMe: true,
                id: options?.messageId || generateMessageID(),
            },
            message: message,
            messageTimestamp: timestamp,
            messageStubParameters: [],
            participant: id.includes('@g.us') ? this.user.jid : null,
            status: WA_MESSAGE_STATUS_TYPE.PENDING
        }
        return WAMessageProto.WebMessageInfo.fromObject (messageJSON)*/

        return message;
    }

    // baileys
    public async prepareMessageContent(message: WAMessageType, type: MessageType, options: MessageOptions) {
        let m: WAMessageContent = {};
        switch (type) {
            case MessageType.text:
            case MessageType.extendedText:
                if (typeof message === 'string') message = { text: message } as WATextMessage;

                if ('text' in message) {
                    /*if (options.detectLinks !== false && message.text.match(URL_REGEX)) {
                        try {
                            message = await this.generateLinkPreview (message.text)
                        } catch (error) { // ignore if fails
                            this.logger.trace(`failed to generate link preview for message '${message.text}': ${error}`)
                        } 
                    }*/
                    m.extendedTextMessage = WAProto.ExtendedTextMessage.fromObject(message as any);
                } else {
                    throw new Error("message needs to be a string or object with property 'text'");
                }
                break;
            case MessageType.location:
            case MessageType.liveLocation:
                m.locationMessage = WAProto.LocationMessage.fromObject(message as any);
                break;
            case MessageType.contact:
                m.contactMessage = WAProto.ContactMessage.fromObject(message as any);
                break;
            case MessageType.contactsArray:
                m.contactsArrayMessage = WAProto.ContactsArrayMessage.fromObject(message as any);
                break;
            case MessageType.groupInviteMessage:
                m.groupInviteMessage = WAProto.GroupInviteMessage.fromObject(message as any);
                break;
            case MessageType.listMessage:
                m.listMessage = WAProto.ListMessage.fromObject(message as any);
                break;
            case MessageType.buttonsMessage:
                m.buttonsMessage = WAProto.ButtonsMessage.fromObject(message as any);
                break;
            case MessageType.templateMessage:
                m.templateMessage = WAProto.TemplateMessage.fromObject(message as any);
                break;
            case MessageType.image:
            case MessageType.sticker:
            case MessageType.document:
            case MessageType.video:
            case MessageType.audio:
                m = await this.prepareMessageMedia(message as Buffer, type, options);
                break;
        }

        return WAProto.Message.fromObject(m);
    }

    // baileys
    protected async fetchRequest(endpoint: string, method: Method = 'GET', body?: any, agent?: Agent, headers?: { [k: string]: string }, followRedirect = true) {
        return got(endpoint, {
            method,
            body,
            followRedirect,
            headers: { Origin: DEFAULT_ORIGIN, ...(headers || {}) },
            agent: { https: agent /*|| this.connectOptions.fetchAgent*/ },
        });
    }

    // baileys
    async prepareMessageMedia(media: WAMediaUpload, mediaType: MessageType, options: MessageOptions = {}) {
        if (mediaType === MessageType.document && !options.mimetype) {
            throw new Error('mimetype required to send a document');
        }

        if (mediaType === MessageType.sticker && options.caption) {
            throw new Error('cannot send a caption with a sticker');
        }

        if (!options.mimetype) {
            options.mimetype = MimetypeMap[mediaType];
        }

        let isGIF = false;
        if (options.mimetype === Mimetype.gif) {
            isGIF = true;
            options.mimetype = MimetypeMap[MessageType.video];
        }

        const requiresDurationComputation = mediaType === MessageType.audio && !options.duration;
        const requiresThumbnailComputation = (mediaType === MessageType.image || mediaType === MessageType.video) && !('thumbnail' in options);
        const requiresOriginalForSomeProcessing = requiresDurationComputation || requiresThumbnailComputation;

        const { mediaKey, encBodyPath, bodyPath, fileEncSha256, fileSha256, fileLength, didSaveToTmpPath } = await encryptedStream(media, mediaType, requiresOriginalForSomeProcessing);

        // url safe Base64 encode the SHA256 hash of the body
        const fileEncSha256B64 = encodeURIComponent(fileEncSha256.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, ''));

        if (requiresThumbnailComputation) {
            await generateThumbnail(bodyPath, mediaType, options);
        }

        if (requiresDurationComputation) {
            try {
                options.duration = await getAudioDuration(bodyPath);
            } catch (error) {
                this.log('failed to obtain audio duration: ' + error.message);
            }
        }

        // send a query JSON to obtain the url & auth token to upload our media
        let json = await this.refreshMediaConn(options.forceNewMediaOptions);

        let mediaUrl: string;
        for (let host of json.hosts) {
            const auth = encodeURIComponent(json.auth); // the auth token
            const url = `https://${host}${MediaPathMap[mediaType]}/${fileEncSha256B64}?auth=${auth}&token=${fileEncSha256B64}`;

            try {
                const { body: responseText } = await this.fetchRequest(url, 'POST', createReadStream(encBodyPath), options.uploadAgent, { 'Content-Type': 'application/octet-stream' });
                const result = JSON.parse(responseText);
                mediaUrl = result?.url;

                if (mediaUrl) break;
                else {
                    json = await this.refreshMediaConn(true);
                    throw new Error(`upload failed, reason: ${JSON.stringify(result)}`);
                }
            } catch (error) {
                const isLast = host === json.hosts[json.hosts.length - 1];
                this.log(`Error in uploading to ${host} (${error}) ${isLast ? '' : ', retrying...'}`);
            }
        }
        if (!mediaUrl) throw new Error('Media upload failed on all hosts');
        // remove tmp files
        await Promise.all([fs.unlink(encBodyPath), didSaveToTmpPath && bodyPath && fs.unlink(bodyPath)].filter(Boolean));

        const message = {
            [mediaType]: MessageTypeProto[mediaType].fromObject({
                url: mediaUrl,
                mediaKey: mediaKey,
                mimetype: options.mimetype,
                fileEncSha256: fileEncSha256,
                fileSha256: fileSha256,
                fileLength: fileLength,
                seconds: options.duration,
                fileName: options.filename || 'file',
                gifPlayback: isGIF || undefined,
                caption: options.caption,
                ptt: options.ptt,
            }),
        };

        return WAProto.Message.fromObject(message); // as WAMessageContent
    }

    public async sendMessageGroupInternal(jid: string | WapJid, message: WAProto.IMessage) {
        const phone = typeof jid == 'string' ? toUserId(jid) : jid.getUser();

        const encodedMessage = new Binary(WAProto.Message.encode(message).finish());
        writeRandomPadMax16(encodedMessage);
        const encoded = encodedMessage.readByteArray();
        const destination = WapJid.create(phone, 'g.us');
        try {
            const { ciphertext, senderKeyDistributionMessage } = await this.waSignal.encryptSenderKeyMsgSignalProto(destination, this.me, encoded);
            const account = await this.storageService.get('account');
            const deviceIdentity = WAProto.ADVSignedDeviceIdentity.encode(account).finish();
            const participants: WapNode[] = [];
            const groupData = await this.getGroupInfo(phone);
            const participantsList = groupData.participants.map((part) => WapJid.create(part.jid, USER_JID_SUFFIX));
            const devices: WapJid[] = await this.getUSyncDevices(participantsList, false);

            for (let index = 0; index < devices.length; index++) {
                const device = devices[index];
                const msg: WAProto.IMessage = {
                    senderKeyDistributionMessage: {
                        groupId: `${phone}@g.us`,
                        axolotlSenderKeyDistributionMessage: new Uint8Array(senderKeyDistributionMessage.serialize()),
                    },
                };
                const e = WapJid.createAD(device.getUser(), device.getAgent(), device.getDevice());
                const participant = await this.createWapNodeParticipant(msg, e);
                if (participant) {
                    participants.push(participant);
                }
            }

            const shouldHaveIdentity = participants.some((p) => {
                return p.content.some((c) => c.attrs.type == 'pkmsg');
            });

            const messageId = generateMessageID();
            const stanza = new WapNode(
                'message',
                {
                    to: destination,
                    id: messageId,
                    phash: await phashV2(participantsList),
                    type: 'text',
                },
                [
                    ...(shouldHaveIdentity ? [new WapNode('participants', {}, participants)] : []),
                    new WapNode(
                        'enc',
                        {
                            v: '2',
                            type: 'skmsg',
                        },
                        new Uint8Array(ciphertext),
                    ),
                    ...(shouldHaveIdentity ? [new WapNode('device-identity', {}, deviceIdentity)] : []),
                ],
            );

            const frame = this.encodeStanza(stanza);
            await this.socketConn.sendFrame(frame);

            return messageId;
        } catch (e) {}
    }

    public async sendMessageInternal(jid: string | WapJid, message: WAProto.IMessage) {
        if ((typeof jid == 'string' && isGroupID(jid)) || (jid instanceof WapJid && jid.isGroup())) {
            return this.sendMessageGroupInternal(jid, message);
        }

        // return
        // if (!this.devices || this.devices.length == 0) {
        //     return this.log('Precisa sincronizar os devices')
        // }

        const account = await this.storageService.get('account');
        const destinationPhone = typeof jid == 'string' ? toUserId(jid) : jid.getUser();
        const destinationJid = new Wid(`${destinationPhone}@c.us`);

        const deviceSentMessage = {
            deviceSentMessage: {
                destinationJid: destinationJid.toString({
                    legacy: !0,
                }),
                message,
            },
        };

        const participants: WapNode[] = [];

        participants.push(await this.createWapNodeParticipant(message, WapJid.createAD(destinationPhone, 0, 0)));

        participants.push(await this.createWapNodeParticipant(deviceSentMessage, WapJid.createAD(this.me.getUser(), 0, 0)));

        const devices: WapJid[] = await this.getUSyncDevices([WapJid.createAD(destinationPhone, 0, 0), WapJid.createAD(this.me.getUser(), 0, 0)]);

        for (let index = 0; index < devices.length; index++) {
            const device = devices[index];

            const isMe = device.getUser() == this.me.getUser();

            const participant = await this.createWapNodeParticipant(isMe ? deviceSentMessage : message, WapJid.createAD(device.getUser(), device.getAgent(), device.getDevice()));
            if (participant) {
                participants.push(participant);
            }
        }

        //console.dir(participants, { depth: null });

        const deviceIdentity = WAProto.ADVSignedDeviceIdentity.encode(account).finish();

        const shouldHaveIdentity = participants.some((p) => {
            return p.content.some((c) => c.attrs.type == 'pkmsg');
        });

        const messageId = generateMessageID();
        const stanza = new WapNode(
            'message',
            {
                id: messageId,
                type: 'text',
                to: WapJid.create(destinationPhone, 's.whatsapp.net'),
            },
            [new WapNode('participants', {}, participants), ...(shouldHaveIdentity ? [new WapNode('device-identity', {}, deviceIdentity)] : [])],
        );

        const frame = this.encodeStanza(stanza);
        await this.socketConn.sendFrame(frame);

        return messageId;
    }

    createWapNodeParticipant = async (body, jidAd) => {
        try {
            const encodedMessage = new Binary(WAProto.Message.encode(body).finish());
            writeRandomPadMax16(encodedMessage);
            const encoded = encodedMessage.readByteArray();
            const proto = await this.waSignal.encryptSignalProto(jidAd, encoded);
            return new WapNode(
                'to',
                {
                    jid: jidAd,
                },
                [
                    new WapNode(
                        'enc',
                        {
                            v: '2',
                            type: proto.type.toLowerCase(),
                        },
                        new Uint8Array(proto.ciphertext),
                    ),
                ],
            );
        } catch (e) {
            if (e && e.name == 'SessionError') {
                await this.ensureIdentityUser(jidAd, true);
                return this.createWapNodeParticipant(body, jidAd);
            }
            return null;
        }
    };

    public async isOnWhatsApp(jid: string) {
        if (isGroupID(jid)) {
            return null;
        }

        const contact = `+${toUserId(jid)}@c.us`;

        const iq = new WapNode(
            'iq',
            {
                id: generateId(),
                to: S_WHATSAPP_NET,
                type: 'get',
                xmlns: 'usync',
            },
            [
                new WapNode(
                    'usync',
                    {
                        sid: generateId(),
                        mode: 'query',
                        last: 'true',
                        index: '0',
                        context: 'interactive',
                    },
                    [
                        new WapNode('query', {}, [new WapNode('contact'), new WapNode('business', {}, [new WapNode('verified_name')])]),
                        new WapNode('list', {}, [new WapNode('user', {}, [new WapNode('contact', {}, contact)])]),
                    ],
                ),
            ],
        );

        const resultFrame = await this.sendMessageAndWait(iq);

        const userNode = resultFrame.child('usync')?.child('list').child('user') ?? null;
        const contactNode = userNode.child('contact');
        const business = userNode.maybeChild('business');

        if (contactNode.attrs.type == 'out') {
            return {
                exists: false,
                jid: null,
                business: false,
            };
        }

        return {
            exists: true,
            jid: userNode.attrs.jid.getUser(),
            business: !!business,
        };
    }

    public async getContactInfo(jids: string[]) {
        const users = jids.map((jid) => {
            return new WapNode(
                'user',
                {
                    jid: WapJid.create(toUserId(jid), USER_JID_SUFFIX),
                },
                null,
            );
        });

        const iq = new WapNode(
            'iq',
            {
                id: generateId(),
                to: S_WHATSAPP_NET,
                type: 'get',
                xmlns: 'usync',
            },
            [
                new WapNode(
                    'usync',
                    {
                        sid: generateId(),
                        mode: 'full',
                        last: 'true',
                        index: '0',
                        context: 'background',
                    },
                    [
                        new WapNode('query', {}, [
                            new WapNode('business', {}, [new WapNode('verified_name')]),
                            new WapNode('status'),
                            new WapNode('picture'),
                            new WapNode('devices', { version: '2' }, null),
                        ]),
                        new WapNode('list', {}, users),
                    ],
                ),
            ],
        );

        const resultFrame: any = await this.sendMessageAndWait(iq);

        // need parse result
        return resultFrame;
    }

    protected getUSyncDevices = async (jids: WapJid[], ignoreZeroDevice = true): Promise<any> => {
        const users = jids.map((jid) => {
            return new WapNode(
                'user',
                {
                    jid,
                },
                null,
            );
        });

        const iq = new WapNode(
            'iq',
            {
                id: generateId(),
                to: S_WHATSAPP_NET,
                type: 'get',
                xmlns: 'usync',
            },
            [
                new WapNode(
                    'usync',
                    {
                        sid: generateId(),
                        mode: 'query',
                        last: 'true',
                        index: '0',
                        context: 'message',
                    },
                    [new WapNode('query', {}, [new WapNode('devices', { version: '2' }, null)]), new WapNode('list', {}, users)],
                ),
            ],
        );

        const resultFrame: any = await this.sendMessageAndWait(iq);
        const devicesToReturn = [];
        for (let index = 0; index < resultFrame.content.length; index++) {
            const result: WapNode = resultFrame.content[index];
            const list = result.content.find((node) => node.tag == 'list');
            if (list) {
                for (let index = 0; index < (list.content || []).length; index++) {
                    const user: WapNode = list.content[index];
                    const userJid: WapJid = user.attrs.jid;
                    for (let index = 0; index < user.content.length; index++) {
                        const devices = deviceParser(user.content[index], this.me);
                        if (devices && devices.deviceList && devices.deviceList.length > 0) {
                            for (let index = 0; index < devices.deviceList.length; index++) {
                                const device = devices.deviceList[index];
                                const jid = WapJid.createAD(userJid.getUser(), 0, device.id);
                                if (ignoreZeroDevice) {
                                    if (jid.getDevice() != 0 && this.me.getDevice() != jid.getDevice()) {
                                        devicesToReturn.push(jid);
                                    }
                                } else {
                                    if (this.me.getDevice() != jid.getDevice()) {
                                        devicesToReturn.push(jid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return devicesToReturn;
    };

    async setGroupName(groupPhone: string, name: string) {
        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                to: WapJid.create(toUserId(groupPhone), 'g.us'),
                type: 'set',
                xmlns: 'w:g2',
            },
            [wapBytes('subject', null, name)],
        );
        await this.sendMessageAndWait(stanza);
    }

    async setGroupDescription(groupPhone: string, description: string) {
        const info = await this.getGroupInfo(groupPhone);
        const prev = info.descriptionId ?? null;

        const content = description
            ? wapBytes(
                  'description',
                  {
                      id: generateMessageID(),
                      ...(prev ? { prev } : {}),
                  },
                  wapBytes('body', null, description),
              )
            : wapBytes(
                  'description',
                  {
                      delete: 'true',
                      ...(prev ? { prev } : {}),
                  },
                  null,
              );
        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                to: WapJid.create(toUserId(groupPhone), 'g.us'),
                type: 'set',
                xmlns: 'w:g2',
            },
            [content],
        );
        await this.sendMessageAndWait(stanza);
    }

    async setGroupSettingsSendMessage(groupPhone: string, onlyAdmin: boolean) {
        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                to: WapJid.create(toUserId(groupPhone), 'g.us'),
                type: 'set',
                xmlns: 'w:g2',
            },
            [new WapNode(onlyAdmin ? 'announcement' : 'not_announcement', {}, null)],
        );
        await this.sendMessageAndWait(stanza);
    }

    async getGroupInvitationCode(groupPhone: string): Promise<string> {
        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                to: WapJid.create(toUserId(groupPhone), 'g.us'),
                type: 'get',
                xmlns: 'w:g2',
            },
            [new WapNode('invite', {}, null)],
        );
        const invitationCode = await this.sendMessageAndWait(stanza);
        return invitationCode.content[0].attrs.code;
    }

    async addOrRemoveGroupParticipants(groupPhone: string, type: 'ADD' | 'REMOVE', participants: string[]) {
        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                to: WapJid.create(toUserId(groupPhone), 'g.us'),
                type: 'set',
                xmlns: 'w:g2',
            },
            [
                new WapNode(
                    type == 'ADD' ? 'add' : 'remove',
                    {},
                    participants.map((p) => {
                        return new WapNode(
                            'participant',
                            {
                                jid: WapJid.create(toUserId(p), USER_JID_SUFFIX),
                            },
                            null,
                        );
                    }),
                ),
            ],
        );
        await this.sendMessageAndWait(stanza);
    }

    async addOrRemoveGroupAdmin(groupPhone: string, type: 'PROMOTE' | 'DEMOTE', participants: string[]) {
        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                to: WapJid.create(toUserId(groupPhone), 'g.us'),
                type: 'set',
                xmlns: 'w:g2',
            },
            [
                new WapNode(
                    type == 'PROMOTE' ? 'promote' : 'demote',
                    {},
                    participants.map((p) => {
                        return new WapNode(
                            'participant',
                            {
                                jid: WapJid.create(toUserId(p), USER_JID_SUFFIX),
                            },
                            null,
                        );
                    }),
                ),
            ],
        );
        await this.sendMessageAndWait(stanza);
    }

    async setGroupImage(groupPhone: string, image: Uint8Array) {
        // needs change to jpg 512x512
        const buffer = await sharp(image).resize(512, 512).jpeg({ quality: 50, progressive: true }).toBuffer();

        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                to: WapJid.create(toUserId(groupPhone), 'g.us'),
                type: 'set',
                xmlns: 'w:profile:picture',
            },
            [new WapNode('picture', { type: 'image' }, new Uint8Array(buffer))],
        );

        const result = await this.sendMessageAndWait(stanza);
        console.dir(result, { depth: null });
    }

    async leaveGroup(groupPhone: string) {
        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                to: G_US,
                type: 'set',
                xmlns: 'w:g2',
            },
            [
                new WapNode('leave', {}, [
                    new WapNode(
                        'group',
                        {
                            id: WapJid.create(toUserId(groupPhone), 'g.us'),
                        },
                        null,
                    ),
                ]),
            ],
        );
        await this.sendMessageAndWait(stanza);
    }

    public async createGroup(name: string, participants: string[]) {
        const participantsNode = participants.map((participant) => {
            return new WapNode('participant', {
                jid: WapJid.create(toUserId(participant), USER_JID_SUFFIX),
            });
        });

        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                type: 'set',
                xmlns: 'w:g2',
                to: G_US,
            },
            [
                new WapNode(
                    'create',
                    {
                        subject: name,
                        key: randomHex(8),
                    },
                    participantsNode,
                ),
            ],
        );

        const result = await this.sendMessageAndWait(stanza);

        return result;
    }

    public async getGroupInfo(groupPhone: string) {
        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                type: 'get',
                xmlns: 'w:g2',
                to: WapJid.create(toUserId(groupPhone), 'g.us'),
            },
            [new WapNode('query', { request: 'interactive' })],
        );

        const result = await this.sendMessageAndWait(stanza);

        const group: WapNode = result.content[0];
        let description = null;
        let descriptionId = null;
        if (group.hasChild('description')) {
            const desc = group.child('description') ?? null;
            if (desc) {
                const body = desc.child('body') ?? null;
                description = body ? body.contentString() : null;
                descriptionId = desc.attrs?.id ?? null;
            }
        }

        const data = <IWAGroupMetadata>{
            name: group.attrs.subject,
            id: group.attrs.id,
            creation: group.attrs.creation,
            creator: group.attrs.creator.toString(),
            restrict: result.hasChild('locked'),
            announce: result.hasChild('announcement'),
            description,
            descriptionId,
            participants: group.content
                .filter((content: WapNode) => content.tag === 'participant')
                .map((content: WapNode) => {
                    return {
                        jid: content.attrs.jid.toString(),
                        isAdmin: content.attrs?.type == 'admin' ? true : false,
                        isSuperAdmin: content.attrs?.type == 'superadmin' ? true : false,
                    };
                }),
        };
        return data;
    }

    public async processProtocolMessage(node: WapNode, msgInfo: any, message: WAProto.IMessage) {
        const protocolMessage = message.protocolMessage;

        if (protocolMessage.historySyncNotification) {
            await this.processHistorySyncNotification(protocolMessage.historySyncNotification);
            if (node.attrs.id) {
                await this.sendReceiptProtocolMessage(node.attrs.id, 'hist_sync');
            }
        }

        if ((node.attrs?.category ?? null) == 'peer') {
            await this.sendReceiptProtocolMessage(node.attrs.id, 'peer_msg');
        }
    }

    private sendReceiptProtocolMessage(id: string, type: string) {
        const receipt = new WapNode('receipt', {
            id,
            type,
            to: WapJid.create(this.me.getUser(), 'c.us'),
        });

        return this.socketConn.sendFrame(this.encodeStanza(receipt));
    }

    public sendDevicesNotificationAck(id: string) {
        const ack = new WapNode('ack', {
            id,
            type: 'account_sync',
            class: 'notification',
            to: WapJid.create(this.me.getUser(), 'c.us'),
        });

        return this.socketConn.sendFrame(this.encodeStanza(ack));
    }

    private async processHistorySyncNotification(historyNotification: WAProto.IHistorySyncNotification) {
        const buffer = await this.downloadFromMediaConn(
            {
                directPath: historyNotification.directPath,
                encFilehash: encodeB64(historyNotification.fileEncSha256),
                filehash: encodeB64(historyNotification.fileSha256),
                mediaKey: historyNotification.mediaKey,
                type: 'md-msg-hist',
                messageType: 'historySync',
            },
            'buffer',
        );

        const dataPromise = new Promise<Buffer>((res) => {
            inflate(buffer as Buffer, (err, result) => {
                if (err) {
                    console.error('err to inflate history sync');
                    return;
                }

                res(result);
            });
        });

        const syncData = WAProto.HistorySync.decode(await dataPromise);

        //console.log('downloaded sync', syncData);
        this.emit('history-sync', syncData);
    }

    public getMessageType(message: WAProto.IMessage) {
        const msg = message.deviceSentMessage ? message.deviceSentMessage.message : message;

        if (msg.imageMessage) {
            return MessageType.image;
        }

        if (msg.stickerMessage) {
            return MessageType.sticker;
        }

        if (msg.videoMessage) {
            return MessageType.video;
        }

        if (msg.audioMessage) {
            return MessageType.audio;
        }

        if (msg.documentMessage) {
            return MessageType.document;
        }

        if (msg.productMessage) {
            return MessageType.product;
        }

        if (msg.conversation) {
            return MessageType.text;
        }

        return null;
    }

    public isMedia(message: WAProto.IMessage) {
        return [MessageType.image, MessageType.video, MessageType.sticker, MessageType.document, MessageType.audio].includes(this.getMessageType(message));
    }

    public async downloadMedia(message: WAProto.IMessage) {
        const type = this.getMessageType(message);

        if (!this.isMedia(message)) {
            console.log('err to download not a media message');
            return null;
        }

        const content = message[type] as any;
        if (!content) {
            console.log('invalid media content');
            return null;
        }

        if (!content.url) {
            return null;

            /*return this.downloadFromMediaConn(
                {
                    directPath: content.directPath,
                    encFilehash: encodeB64(content.fileEncSha256),
                    filehash: encodeB64(content.fileSha256),
                    mediaKey: content.mediaKey,
                    type: 'md-msg-hist',
                    messageType: 'historySync',
                },
                'buffer',
            );*/
        }

        return this.downloadMediaMessage('buffer', content.url, content.mediaKey, type);
    }

    private async downloadMediaMessage(type: string, url: string, mediaKey: Uint8Array, messageType: MessageType) {
        const stream = await downloadAndDecrypt(url, mediaKey, messageType);
        if (type === 'buffer') {
            let buffer = Buffer.from([]);
            for await (const chunk of stream) {
                buffer = Buffer.concat([buffer, chunk]);
            }
            return buffer;
        }
        return stream;
    }

    private async downloadFromMediaConn(media: any, type: 'buffer' | 'stream' = 'buffer', forceGet = false) {
        const mediaConn = await this.refreshMediaConn(forceGet);

        let url = media.directPath ?? null;
        if (!url) {
            throw new Error('invalid media url');
        }

        for (const host of mediaConn.hosts) {
            const reqUrl = `https://${host}${url}&hash=${media.encFilehash}&mms-type=${media.type}&__wa-mms=`;

            this.log('downloading media', reqUrl);

            try {
                const data = await this.downloadMediaMessage(type, reqUrl, media.mediaKey, media.messageType);

                return data;
            } catch (err) {
                console.log('err to download', err);
            }
        }
    }

    private async refreshMediaConn(forceGet = false) {
        if (!this.mediaConn || forceGet || new Date().getTime() - this.mediaConn.fetchDate.getTime() > this.mediaConn.TTL * 1000) {
            this.mediaConn = await this.sendQueryMediaConn();
            this.mediaConn.fetchDate = new Date();
        }

        return this.mediaConn;
    }

    private async sendQueryMediaConn() {
        const stanza = new WapNode(
            'iq',
            {
                id: generateId(),
                type: 'set',
                xmlns: 'w:m',
                to: S_WHATSAPP_NET,
            },
            [new WapNode('media_conn')],
        );

        const result = await this.sendMessageAndWait(stanza);

        const mediaConn = result.child('media_conn');
        if (!mediaConn) {
            throw new Error('invalid media conn');
        }

        const hosts = mediaConn.mapChildrenWithTag('host', (host: WapNode) => {
            return host.attrs.hostname;
        });

        return <IMediaConn>{
            auth: mediaConn.attrString('auth'),
            TTL: mediaConn.attrInt('ttl'),
            authTTL: mediaConn.attrInt('auth_ttl'),
            maxBuckets: mediaConn.attrInt('max_buckets'),
            hosts,
        };
    }

    private createKeepAlive = () => {
        this.keepAliveTimer = setInterval(() => {
            this.socketConn.sendFrame(
                this.encodeStanza(
                    new WapNode(
                        'iq',
                        {
                            id: generateId(),
                            to: S_WHATSAPP_NET,
                            type: 'get',
                            xmlns: 'w:p',
                        },
                        [new WapNode('ping')],
                    ),
                ),
            );
        }, this.KEEP_ALIVE_INTERVAL);
    };

    private destroyKeepAlive = () => {
        if (this.keepAliveTimer) {
            clearInterval(this.keepAliveTimer);
            this.keepAliveTimer = null;
        }
    };

    destroy() {
        this.socketConn.close();
        delete this.socketConn;
        this.destroyKeepAlive();
        delete sessions[this.sessionName];
    }
}

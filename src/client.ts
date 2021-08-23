import { randomBytes, areBuffersEqual, HEADER, CERT_ISSUER, BIG_ENDIAN_CONTENT, KEY_BUNDLE_TYPE, xmppPreKey, xmppSignedPreKey, MESSAGE_TYPE } from './utils/Utils';
import { Socket } from './socket/Socket';
import { FrameSocket } from './socket/FrameSocket';
import { NoiseHandshake } from './socket/NoiseHandshake';
import { toLowerCaseHex } from './utils/HexHelper';

import zlib from 'zlib';
import { generatePayloadRegister } from './payloads/RegisterPayload';
import { Binary } from './proto/Binary';
import { encodeStanza, generateId, decodeStanza } from './proto/Stanza';
import { calculateSignature, generateIdentityKeyPair, generateRegistrationId, generateSignedPreKey, Key, KeyPair, sharedKey, SignedKeyPair, verifySignature } from './utils/Curve';
import { WapNode } from './proto/WapNode';
import * as QR from 'qrcode-terminal';
import { decodeB64, encodeB64 } from './utils/Base64';
import { S_WHATSAPP_NET, WapJid } from './proto/WapJid';
import { generatePayloadLogin } from './payloads/LoginPayload';
import { hmacSha256 } from './utils/HKDF';
import { proto as WAProto } from './proto/WAMessage';

import { StorageService } from './services/StorageService';
import { NoiseSocket } from './socket/NoiseSocket';
import { StorageSignal } from './signal/StorageSignal';
import { WaSignal } from './signal/Signal';

const sessions = {};

interface Props {
    sessionName: string;
    /**
     * @description Callback stops when socket is closed
     */
    onSocketClose(err: Error): void;
}

export class WaClient {
    private KEEP_ALIVE_INTERVAL = 1e4 * Math.random() + 2e4;
    private keepAliveTimer: NodeJS.Timer;

    private waSignal: WaSignal;
    private storageSignal: StorageSignal;
    private sessionName: string;
    private socket: Socket;
    private storageService: StorageService;
    private frame: FrameSocket;
    private noise: NoiseHandshake;
    private me: WapJid;
    private socketConn: NoiseSocket;

    private registrationId: number;
    /** keys */
    private ephemeralKeyPair: KeyPair;
    private signedIdentityKey: KeyPair;
    private noiseKey: KeyPair;
    private signedPreKey: SignedKeyPair;
    private advSecretKey: string;

    /** events */
    private onSocketClose: Function;

    constructor({ sessionName, onSocketClose }: Props) {
        if (sessions[sessionName]) {
            throw new Error(`SessionName "${sessionName}" already exists`);
        }
        sessions[sessionName] = this;
        this.sessionName = sessionName;
        this.onSocketClose = onSocketClose;
        this.storageService = new StorageService('./sessions');
        this.initConfig();
    }

    private initConfig() {
        this.storageService.init(`${this.sessionName.replace(/ /g, '-')}.json`);
        this.storageSignal = new StorageSignal(this.storageService);
        this.waSignal = new WaSignal(this.storageService, this.storageSignal);
    }

    createConnection = () => {
        return new Promise((resolve) => {
            this.socket = new Socket();
            this.socket.open();
            this.ephemeralKeyPair = generateIdentityKeyPair();
            this.socket.onOpen = this.handleSocketOpen(() => resolve(true));
        });
    };

    private handleSocketOpen = (cb) => async () => {
        try {
            await this.configureConnection();
            this.createKeepAlive();
            cb();
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

        console.log('received server hello', toLowerCaseHex(serverHelloEnc));
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
        this.socketConn.onClose = this.onNoiseSocketClose;
        this.socketConn.setOnFrame(this.onNoiseNewFrame);
    };

    private onNoiseSocketClose = () => {
        this.destroyKeepAlive();
        if (this.onSocketClose) {
            this.onSocketClose();
        }
    };

    private unpackStanza = async (e): Promise<Binary> => {
        let data = new Binary(e);
        if (2 & data.readUint8()) {
            return new Promise((res) => {
                zlib.inflate(data.readByteArray(), (err, result) => {
                    if (err) {
                        console.error('err to decode stanza');
                        return;
                    }

                    res(new Binary(result));
                });
            });
        }

        return data;
    };

    private verifyDeviceIdentityAccountSignature = (account: any, identityKeyPair: KeyPair) => {
        const msg = Binary.build(new Uint8Array([6, 0]), account.details, identityKeyPair.pubKey).readByteArray();
        return verifySignature(new Uint8Array(account.accountSignatureKey), msg, new Uint8Array(account.accountSignature));
    };

    private generateDeviceSignature = (account: any, identityKeyPair: any) => {
        const msg = Binary.build(new Uint8Array([6, 1]), account.details, identityKeyPair.pubKey, account.accountSignatureKey).readByteArray().buffer;
        return calculateSignature(identityKeyPair.privKey, new Uint8Array(msg));
    };

    private uploadPreKeys = async () => {
        const registrationId = this.storageService.get<number>('registrationId');
        const identityKey = this.storageService.get<KeyPair>('signedIdentityKey');
        const signedPreKey = this.storageService.get<SignedKeyPair>('signedPreKey');
        if (!identityKey || !signedPreKey) {
            console.log('invalid identityKey or signedPreKey from uploadPreKeys');
            return;
        }
        const preKeys = await this.waSignal.getOrGenPreKeys(30);
        if (preKeys.length == 0) {
            console.log('No preKey is available');
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
        this.socketConn.sendFrame(encodeStanza(stanza));
        await this.waSignal.markKeyAsUploaded(lastId.keyId);
        await this.waSignal.putServerHasPreKeys(true);
    };

    private sendPassiveIq = async (e: boolean) => {
        const stanza = new WapNode(
            'iq',
            {
                to: S_WHATSAPP_NET,
                xmlns: 'passive',
                type: 'set',
                id: generateId(),
            },
            [new WapNode(e ? 'passive' : 'active', null)],
        );
        this.socketConn.sendFrame(encodeStanza(stanza));
    };

    private parsePairDevice = async (node: WapNode) => {
        //var e = 6 === _.length ? 6e4 : 2e4
        const refs = node.content[0].content.map((node: WapNode) => {
            return node.contentString();
        });

        console.log('sending ok to server id: ', node.attrs.id);
        // send ok
        const iq = new WapNode('iq', {
            to: S_WHATSAPP_NET,
            type: 'result',
            id: node.attrs.id,
        });

        const nodeEnc = encodeStanza(iq);
        this.socketConn.sendFrame(nodeEnc);

        console.log('refs', refs);

        const ref = refs.shift();

        const noiseKeyB64 = encodeB64(this.noiseKey.pubKey);
        const identityKeyB64 = encodeB64(this.signedIdentityKey.pubKey);
        const advB64 = this.advSecretKey;
        const qrString = [ref, noiseKeyB64, identityKeyB64, advB64].join(',');

        QR.generate(qrString, { small: true });
        console.log(qrString);
    };

    private parseStreamError = async (node: WapNode) => {
        const code = node.attrs.code ?? null;
        if (!code) {
            console.log('invalid code in stream:error');
            return;
        }
        if (code == '515') {
            console.log('restarting socket');
            this.socketConn.restart();
        }
        if (code == '516') {
            // start logout
        }
    };

    private parseStreamFailure = async (node: WapNode) => {
        const reason = node.attrs.reason ?? null;
        if (reason == '401') {
            // disconnected by cell phone
            console.log('restarting socket');
            this.storageService.clearAll();
            this.socketConn.restart();
        }
    };

    private parseSuccess = async (node: WapNode) => {
        console.log('success');
        const serverHasPreKeys = await this.waSignal.getServerHasPreKeys();
        if (!serverHasPreKeys) {
            await this.uploadPreKeys();
        }

        await this.sendPassiveIq(false);
    };

    private parsePairSuccess = async (node: WapNode) => {
        const pair: WapNode = node.content[0];

        const id = node.attrs.id;
        const deviceIdentityBytes = pair.getContentByTag('device-identity')?.content;
        const businessName = pair.getContentByTag('biz')?.attrs?.name ?? null;
        const wid = pair.getContentByTag('device')?.attrs?.jid ?? null;

        const { details, hmac } = WAProto.ADVSignedDeviceIdentityHMAC.decode(deviceIdentityBytes);

        if (!details || !hmac) {
            console.log('invalid device details or hmac');
            return;
        }

        const sendNotAuthozired = () =>
            this.socketConn.sendFrame(
                encodeStanza(
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

        const advSecret = decodeB64(await this.storageService.get('advSecretKey'));
        const advSign = await hmacSha256(advSecret, details);

        if (encodeB64(hmac) !== encodeB64(new Uint8Array(advSign))) {
            console.log('invalid hmac from pair-device success');

            sendNotAuthozired();
            // TODO MAKE CLEAR THE STORAGE KEYS
            return;
        }

        const account = WAProto.ADVSignedDeviceIdentity.decode(details);
        const { accountSignatureKey, accountSignature } = account;
        if (!accountSignatureKey || !accountSignature) {
            console.log('invalid accountSignature or accountSignatureKey');
            return;
        }

        const identityKeyPair = await this.storageService.get('signedIdentityKey');

        if (!this.verifyDeviceIdentityAccountSignature(account, identityKeyPair)) {
            console.log('invalid device signature');
            sendNotAuthozired();
            return;
        }

        account.deviceSignature = this.generateDeviceSignature(account, identityKeyPair);

        await this.waSignal.putIdentity(this.waSignal.createSignalAddress(wid.toString(), 0), new Key(this.waSignal.toSignalCurvePubKey(accountSignatureKey)));

        const keyIndex = WAProto.ADVDeviceIdentity.decode(account.details).keyIndex;

        const acc = account.toJSON();
        acc.accountSignatureKey = undefined;

        const accountEnc = WAProto.ADVSignedDeviceIdentity.encode(acc).finish();

        const stanza = encodeStanza(
            new WapNode(
                'iq',
                {
                    to: S_WHATSAPP_NET,
                    type: 'result',
                    id,
                },
                [
                    new WapNode('pair-device-sign', null, [
                        new WapNode(
                            'device-identity',
                            {
                                'key-index': `${keyIndex}`,
                            },
                            accountEnc,
                        ),
                    ]),
                ],
            ),
        );
        this.socketConn.sendFrame(stanza);
        await this.storageService.save('me', wid);
    };

    private parseMessage = async (node: WapNode) => {
        const encMap: any[] = node.mapChildrenWithTag('enc', (node: WapNode) => {
            return {
                e2eType: node.attrs.type,
                mediaType: node.attrs?.mediatype ?? null,
                ciphertext: node.contentBytes(),
                retryCount: node.attrs?.count ?? 0,
            };
        });

        const deviceIdentity = node.maybeChild('device-identity');
        const deviceIdentityBytes = deviceIdentity ? deviceIdentity.contentBytes() : null;

        const msgInfo = ((node: WapNode, encMap: any[]) => {
            let ephSettings: {
                [key: string]: string;
            } = {};
            let participants: WapJid[] = [];

            let info: any = {
                externalId: node.attrs.id,
                ts: node.attrs.t,
                edit: node.attrs?.edit ?? -1,
                isHsm: !!node.attrs?.hsm,
                count: node.attrs?.count ?? null,
                pushname: node.attrs?.notify ?? null,
                category: node.attrs?.category ?? null,
                offline: node.attrs?.offline ?? null,
            };

            const from: WapJid = node.attrs.from;
            const recipient: WapJid = node.attrs?.recipient ?? null;
            const participant: WapJid = node.attrs?.participant ?? null;
            const isDirect = encMap.every((enc) => enc.e2eType != 'skmsg');
            const isRetry = encMap.some((enc) => enc.retryCount > 0);

            console.log({
                from,
                recipient,
                participants,
                isDirect,
                isRetry,
            });

            const participantsNode = node.maybeChild('participants');
            if (participantsNode) {
                node.forEachChildWithTag('to', (node: WapNode) => {
                    const jid: WapJid = node.attrs?.jid;
                    const ephSetting = node.attrs?.eph_setting ?? null;

                    participants.push(node.attrs.jid);

                    if (ephSetting) {
                        ephSettings[jid.toString()] = ephSetting;
                    }
                });
            }

            const isPeer = (jid: WapJid) => {
                const me = this.storageService.get<WapJid>('me');
                console.log('me', me);
                return jid.equals(me);
            };

            if (from.isUser()) {
                if (recipient) {
                    if (!isPeer(from)) {
                        throw new Error('recipient on non peer chat message');
                    }

                    return {
                        ...info,
                        type: MESSAGE_TYPE.CHAT,
                        chat: recipient,
                        author: from,
                    };
                }

                return {
                    type: MESSAGE_TYPE.CHAT,
                    chat: from,
                    author: from,
                };
            }

            if (from.isGroup()) {
                if (!participant) {
                    throw new Error('group message with no participant');
                }

                return {
                    ...info,
                    type: MESSAGE_TYPE.GROUP,
                    chat: from,
                    author: participant,
                    isDirect,
                };
            }

            if (from.isBroadcast() && !from.isStatusV3()) {
                if (!participant) {
                    throw new Error('broadcast message with no participant');
                }

                if (isPeer(participant)) {
                    if (participants.length == 0) {
                        if (!isRetry) {
                            throw new Error('peer broadcast message with no participants node');
                        }

                        participants = [];
                    }

                    return {
                        ...info,
                        type: MESSAGE_TYPE.PEER_BROADCAST,
                        chat: from,
                        author: participant,
                        isDirect,
                        bclParticipants: participants,
                        bclHashValidated: false,
                        bclEphSettings: ephSettings,
                    };
                }

                return {
                    ...info,
                    type: MESSAGE_TYPE.OTHER_BROADCAST,
                    chat: from,
                    author: participant,
                    isDirect,
                    ephSetting: node.attrs?.eph_setting ?? null,
                };
            }

            if (from.isBroadcast() && from.isStatusV3()) {
                if (!participant) {
                    throw new Error('status message with no participant');
                }

                if (isPeer(participant) && isDirect) {
                    if (participants.length == 0) {
                        return {
                            ...info,
                            type: MESSAGE_TYPE.DIRECT_PEER_STATUS,
                            chat: from,
                            author: participant,
                            isDirect,
                        };
                    }

                    return {
                        ...info,
                        type: MESSAGE_TYPE.DIRECT_PEER_STATUS,
                        chat: from,
                        author: participant,
                        bclParticipants: participants,
                        bclHashValidated: false,
                    };
                }

                return {
                    ...info,
                    type: MESSAGE_TYPE.OTHER_STATUS,
                    chat: from,
                    author: participant,
                    isDirect,
                };
            }

            throw new Error('Unrecognized message type');
        })(node, encMap);

        const msgMeta = ((node: WapNode, encMap: any[]) => {
            const isUnavailable = node.hasChild('unavailable');
            if (!isUnavailable && encMap.length == 0) {
                throw new Error('incomingMsgParser: to have enc node children');
            }

            return {
                isUnavailable,
                type: node.attrs.type,
                rawTs: node.attrs.t,
                urlNumber: node.hasChild('url_number'),
                urlText: node.hasChild('url_text'),
            };
        })(node, encMap);

        const bizInfo = ((node: WapNode) => {
            const verifiedNameCert = node.hasChild('verified_name') ? node.child('verified_name').contentBytes() : null;
            const verifiedLevel = node.attrs?.verified_level ?? null;
            const verifiedNameSerial = node.attrs?.verified_name ?? -1;
            const biz = node.maybeChild('biz');
            let privacyMode = null;

            if (biz != null) {
                const actualActors = biz.attrs?.actual_actors ?? null;
                const hostStorage = biz.attrs?.host_storage ?? null;
                const privacyModeTs = biz.attrs?.privacy_mode_ts ?? null;

                if (actualActors && hostStorage && privacyModeTs) {
                    privacyMode = {
                        actualActors,
                        hostStorage,
                        privacyModeTs,
                    };
                }
            }

            return {
                verifiedNameCert,
                verifiedLevel: verifiedLevel,
                verifiedNameSerial,
                privacyMode,
            };
        })(node);

        const paymentInfo = null; // TODO PAYMENT INFO

        /*console.log({
            encs: encMap,
            msgInfo,
            msgMeta,
            bizInfo,
            paymentInfo,
            deviceIdentity: deviceIdentityBytes,
        });*/

        const getFrom = (msg: any) => (msg.type == MESSAGE_TYPE.CHAT ? msg.author : msg.chat);

        const unpad = (e) => {
            const t = new Uint8Array(e);
            if (0 === t.length) {
                throw new Error('unpadPkcs7 given empty bytes');
            }

            var r = t[t.length - 1];
            if (r > t.length) {
                throw new Error(`unpad given ${t.length} bytes, but pad is ${r}`);
            }

            return new Uint8Array(t.buffer, t.byteOffset, t.length - r);
        };

        for (const enc of encMap) {
            switch (enc.e2eType) {
                case 'skmsg':
                    console.log('skmsg');
                    break;
                case 'pkmsg':
                case 'msg':
                    const s = getFrom(msgInfo);
                    const n = s.isUser() ? s : msgInfo.author;

                    const result = await this.waSignal.decryptSignalProto(n, enc.e2eType, Buffer.from(enc.ciphertext));

                    const messageProto = WAProto.Message.decode(unpad(result));

                    console.log('decryptMessage', {
                        ...msgInfo,
                        ...messageProto,
                    });
                    break;

                default:
                    break;
            }
        }
    };

    private parseNotification = (stanza: WapNode) => {
        console.log('recevied notification', stanza.content[0]);
        console.log('devices', stanza.content[0].content);
    };

    private handleStanza = async (stanza: WapNode) => {
        if (!(stanza instanceof WapNode)) {
            return null;
        }
        const tag = stanza.tag;
        console.log('received tag node', tag);
        if (tag == 'iq' && stanza.content) {
            switch (stanza.content[0].tag) {
                case 'pair-device':
                    await this.parsePairDevice(stanza);
                    break;

                case 'pair-success':
                    await this.parsePairSuccess(stanza);
                    break;

                default:
                    console.log('received tag from iq: ', stanza?.content[0]?.tag);
                    break;
            }
        }

        if (tag == 'stream:error') {
            await this.parseStreamError(stanza);
        }

        if (tag == 'success') {
            await this.parseSuccess(stanza);
        }

        if (tag == 'failure') {
            await this.parseStreamFailure(stanza);
        }

        if (tag == 'message') {
            await this.parseMessage(stanza);
        }

        if (tag == 'notification') {
            await this.parseNotification(stanza);
        }
    };

    private onNoiseNewFrame = async (frame) => {
        const data = await this.unpackStanza(frame);
        const stanza = decodeStanza(data);
        await this.handleStanza(stanza);
        console.log(stanza);
    };

    private createFanoutStanza = async (message: WAProto.IMessage, devices: any, options?: any) => {};

    private sendMessage = async (jid: WapJid, message: WAProto.IMessage) => {};

    private createKeepAlive = () => {
        this.keepAliveTimer = setInterval(() => {
            console.log('send ping to server');
            this.socketConn.sendFrame(
                encodeStanza(
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
        }
    };

    destroy() {
        this.socketConn.close();
        this.socket.close();
        delete sessions[this.sessionName]
    }
}

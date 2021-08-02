import { ProtocolAddress } from './ProtocolAddress';
import { storageService } from './../services/StorageService';
import { generatePreKey, Key, PreKey } from './../utils/Curve';
import libsignal from 'libsignal';
import { storageSignal } from './StorageSignal';
import { WapJid } from './../proto/WapJid';

interface IIdentity {
    identifier: ProtocolAddress;
    identifierKey: Key;
}

export const toSignalCurvePubKey = (pubKey: any) => {
    const newPub = new Uint8Array(33);
    newPub.set([5], 0);
    newPub.set(pubKey, 1);

    return newPub;
};

export const createSignalAddress = (name: string, deviceId: number) => new ProtocolAddress(name, deviceId);

export const putIdentity = async (address: ProtocolAddress, key: Key) => {
    const identities = await storageService.getOrSave<IIdentity[]>('identities', () => []);

    identities.push({
        identifier: address,
        identifierKey: key,
    });

    await storageService.save('identities', identities);
};

export const putMeta = async (metaName: string, value: any) => {
    const metas = await storageService.getOrSave('metas', () => {});

    metas[metaName] = value;

    storageService.save('metas', metas);
};

export const getMeta = async <T = any>(metaName: string): Promise<T> => {
    const metas = await storageService.getOrSave('metas', () => {
        return {};
    });

    return metas[metaName] ?? null;
};

export const getPreKeysByRange = async (range: number, limit: number) => {
    const preKeys = await storageService.getOrSave<PreKey[]>('preKeys', () => []);

    return preKeys.filter((keys) => keys.keyId > range - 1).slice(0, limit);
};

export const savePreKeys = async (keys: PreKey[]) => {
    if (!keys) {
        return;
    }

    const lastKey = keys[keys.length - 1];
    await putMeta('nextPreKeyId', lastKey.keyId + 1);

    const preKeys = await storageService.getOrSave<PreKey[]>('preKeys', () => []);

    keys.map((key) => {
        const exists = preKeys.find((p) => p.keyId == key.keyId);
        if (exists) {
            throw Error(`preKey id ${key.keyId} already exists`);
        }

        preKeys.push(key);
    });

    await storageService.save('preKeys', preKeys);

    return true;
};

export const getOrGenPreKeys = async (range: number) => {
    const firstUnuploadedId = (await getMeta('firstUnuploadedId')) ?? 1;
    const nextPreKeyId = (await getMeta('nextPreKeyId')) ?? 1;

    const avaliable = nextPreKeyId - firstUnuploadedId;
    const remaining = range - avaliable;

    if (remaining <= 0) {
        console.log(`getOrGenPreKeys: no prekey needs to be generated, avaliable: ${avaliable}, need: ${range}`);
        return getPreKeysByRange(firstUnuploadedId, range);
    }

    const keys = ((range: number, limit: number) => {
        const out = [];
        for (let a = range; a < limit; a++) {
            out.push(a);
        }
        return out;
    })(nextPreKeyId, nextPreKeyId + remaining).map((keyId) => generatePreKey(keyId));

    await savePreKeys(keys);

    return getPreKeysByRange(firstUnuploadedId, range);
};

export const markKeyAsUploaded = async (id: number) => {
    const firstUnuploadedId = await getMeta('firstUnuploadedId');
    const nextPreKeyId = (await getMeta('nextPreKeyId')) ?? 1;

    if (id < 0 || !nextPreKeyId || id >= nextPreKeyId) {
        throw Error(`markKeyAsUploaded: key ${id} is out of boundary.`);
    }

    await putMeta('firstUnuploadedId', firstUnuploadedId ? Math.max(firstUnuploadedId, id + 1) : id + 1);
};

export const putServerHasPreKeys = async (flag: boolean) => {
    await putMeta('serverHasPreKeys', flag);
};

export const getServerHasPreKeys = async () => {
    return getMeta<boolean>('serverHasPreKeys');
};

export const createLibSignalAddress = (e: WapJid) => {
    if (!(e.isUser() || e.isServer() || e.isPSA())) throw new Error(`Jid ${e.toString()} is not fully qualified, jid.server should be "s.whatsapp.net"`);

    return new libsignal.ProtocolAddress(e.getSignalAddress(), 0);
};

export const decryptSignalProto = async (e, t, r) => {
    try {
        const session = new libsignal.SessionCipher(storageSignal, createLibSignalAddress(e));
        switch (t) {
            case 'pkmsg':
                const keys = await session.listAllKeys(r);
                console.log('>>>stolenkeys', keys);
                // setTimeout(async () => {
                //   console.log('pppp', await session.decryptPreKeyWhisperMessage(r, keys));
                // }, 5000);
                const id = Math.random();
                console.log('pre-id', id, Date.now());
                setTimeout(() => {
                  console.log(id, Date.now());
                }, 3000);
                
                // await new Promise((resolve) => setTimeout(() => resolve, 5000));
                const ret = await session.decryptPreKeyWhisperMessage(r, keys)
                return ret;
                // return session.decryptPreKeyWhisperMessage(r);
            case 'msg':
                return session.decryptWhisperMessage(r);
            default:
                return Promise.reject(`decryptSignalProto: Received unsupported msg type ${t}`);
        }
    } catch (err) {
        if (e && 'call_failure' === e.reason && e.value && 'number' == typeof e.value.result) {
            console.log(`decryptSignalProto error code ${e.value.result}`);
        } else {
            if (e && 'MessageCounterError' === e.name) {
                //return Promise.reject(new i.SignalMessageCounterError(e));
                console.log('SignalMessageCounterError', e);
                throw err;
            } 

            console.log(`decryptSignalProto js error ${e}`);
        }

        throw err;
    }
};

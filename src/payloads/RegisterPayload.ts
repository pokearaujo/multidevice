import { KeyPair, SignedKeyPair } from "../utils/Curve";
import { intToBytes, VERSION_ENCODED } from "../utils/Utils";
import { proto as WAProto } from '../../WAMessage/WAMessage';

export const generatePayloadRegister = (
  registrationId: number,
  keyPair: KeyPair,
  signedPreKey: SignedKeyPair
) => {
  const appVersionBuf = new Uint8Array(Buffer.from(VERSION_ENCODED, "base64"));

  const companion = {
    os: "Windows",
    version: {
      primary: 10,
      secondary: undefined,
      tertiary: undefined,
    },
    platformType: 1,
    requireFullSync: false,
  };

  const companionProto = WAProto.CompanionProps.encode(companion).finish();

  const registerPayload = {
    connectReason: 1,
    connectType: 1,
    passive: false,
    regData: {
      buildHash: appVersionBuf,
      companionProps: companionProto,
      eRegid: intToBytes(4, registrationId),
      eKeytype: intToBytes(1, 5),
      eIdent: keyPair.pubKey,
      eSkeyId: intToBytes(3, signedPreKey.keyId),
      eSkeyVal: signedPreKey.keyPair.pubKey,
      eSkeySig: signedPreKey.signature,
    },
    userAgent: {
      appVersion: {
        primary: 2,
        secondary: 2204,
        tertiary: 14,
      },
      platform: 14,
      releaseChannel: 0,
      mcc: "000",
      mnc: "000",
      osVersion: "0.1",
      manufacturer: "",
      device: "Desktop",
      osBuildNumber: "0.1",
      localeLanguageIso6391: "en",
      localeCountryIso31661Alpha2: "en",
    },
    webInfo: {
      webSubPlatform: 0,
    },
  };
 
  return WAProto.ClientPayload.encode(registerPayload).finish();
};

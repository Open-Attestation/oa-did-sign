import { utils, v2, v3, ProofType, ProofPurpose } from "@govtechsg/open-attestation";
import { SigningKey } from "src/types";
import { sign } from "../signer";

export enum SUPPORTED_SIGNING_ALGORITHM {
  Secp256k1VerificationKey2018 = "Secp256k1VerificationKey2018",
}

export const signV2Document = async <T extends v2.OpenAttestationDocument>(
  document: v2.SignedWrappedDocument<T> | v2.WrappedDocument<T>,
  algorithm: SUPPORTED_SIGNING_ALGORITHM,
  publicKey: string,
  privateKey: string
): Promise<v2.SignedWrappedDocument<T>> => {
  const signingKey: SigningKey = { private: privateKey, public: publicKey };
  const merkleRoot = `0x${document.signature.merkleRoot}`;
  const signature = await sign(algorithm, merkleRoot, signingKey);
  const proof = {
    type: ProofType.OpenAttestationSignature2018,
    created: new Date().toISOString(),
    proofPurpose: ProofPurpose.AssertionMethod,
    verificationMethod: publicKey,
    signature,
  };
  return {
    ...document,
    proof: utils.isSignedWrappedV2Document(document) ? [...document.proof, proof] : [proof],
  };
};

export const signV3Document = async <T extends v3.OpenAttestationDocument>(
  document: v3.SignedWrappedDocument<T> | v3.WrappedDocument<T>,
  algorithm: SUPPORTED_SIGNING_ALGORITHM,
  publicKey: string,
  privateKey: string
): Promise<v3.SignedWrappedDocument<T>> => {
  const signingKey: SigningKey = { private: privateKey, public: publicKey };
  const merkleRoot = `0x${document.proof.merkleRoot}`;
  const signature = await sign(algorithm, merkleRoot, signingKey);
  const proof: v3.VerifiableCredentialProofSigned = {
    ...document.proof,
    key: publicKey,
    signature,
  };
  return { ...document, proof };
};

export async function signDocument<T extends v3.OpenAttestationDocument>(
  document: v3.SignedWrappedDocument<T> | v3.WrappedDocument<T>,
  algorithm: SUPPORTED_SIGNING_ALGORITHM,
  publicKey: string,
  privateKey: string
): Promise<v3.SignedWrappedDocument<T>>;
export async function signDocument<T extends v2.OpenAttestationDocument>(
  document: v2.SignedWrappedDocument<T> | v2.WrappedDocument<T>,
  algorithm: SUPPORTED_SIGNING_ALGORITHM,
  publicKey: string,
  privateKey: string
): Promise<v2.SignedWrappedDocument<T>>;
export async function signDocument(
  document: any,
  algorithm: SUPPORTED_SIGNING_ALGORITHM,
  publicKey: string,
  privateKey: string
) {
  switch (true) {
    case utils.isWrappedV2Document(document):
      return signV2Document(document, algorithm, publicKey, privateKey);
    case utils.isWrappedV3Document(document):
      return signV3Document(document, algorithm, publicKey, privateKey);
    default:
      throw new Error("Unsupported document type: Only OpenAttestation v2 & v3 documents can be signed");
  }
}

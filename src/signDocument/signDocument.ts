import {
  WrappedDocument,
  SignedWrappedDocument,
  utils,
  v2,
  v3,
  ProofType,
  ProofPurpose,
} from "@govtechsg/open-attestation";
import { SigningKey } from "src/types";
import { sign } from "../signer";

export const signMerkleRoot = async (algorithm: string, merkleRoot: string, key: SigningKey) =>
  sign(algorithm, merkleRoot, key);

export enum SUPPORTED_SIGNING_ALGORITHM {
  Secp256k1VerificationKey2018 = "Secp256k1VerificationKey2018",
}

export const signDocument = async <T extends v2.OpenAttestationDocument | v3.OpenAttestationDocument>(
  document: SignedWrappedDocument<T> | WrappedDocument<T>,
  algorithm: SUPPORTED_SIGNING_ALGORITHM,
  publicKey: string,
  privateKey: string
): Promise<SignedWrappedDocument<any>> => {
  if (!utils.isWrappedV2Document(document) && !utils.isWrappedV3Document(document))
    throw new Error("Only v2 & v3 document is supported now");

  const merkleRoot = utils.isWrappedV3Document(document)
    ? `0x${document.proof.merkleRoot}`
    : `0x${document.signature.merkleRoot}`;
  const signingKey: SigningKey = { private: privateKey, public: publicKey };
  const signature = await signMerkleRoot(algorithm, merkleRoot, signingKey);

  if (utils.isWrappedV3Document(document)) {
    if (utils.isSignedWrappedV3Document(document)) throw new Error("Document has been signed.");

    const proof: v3.VerifiableCredentialProofSigned = {
      ...document.proof,
      key: publicKey,
      signature,
    };
    const signWrapped: v3.SignedWrappedDocument = { ...document, proof };
    return signWrapped;
  } else {
    const proof = {
      type: ProofType.OpenAttestationSignature2018,
      created: new Date().toISOString(),
      proofPurpose: ProofPurpose.AssertionMethod,
      verificationMethod: publicKey,
      signature,
    };

    return utils.isSignedWrappedV2Document(document)
      ? { ...document, proof: [...document.proof, proof] }
      : { ...document, proof: [proof] };
  }
};

import { v2, v3 } from "@govtechsg/open-attestation";
import { signDocument, SUPPORTED_SIGNING_ALGORITHM } from ".";
import rawWrappedDocumentV2 from "../../test/fixtures/v2/did-wrapped.json";
import rawWrappedDocumentV3 from "../../test/fixtures/v3/did-wrapped.json";

const wrappedDocumentV2 = rawWrappedDocumentV2 as v2.WrappedDocument;
const wrappedDocumentV3 = rawWrappedDocumentV3 as v3.WrappedDocument;

describe("signDocument", () => {
  describe("v2", () => {
    it("should sign a document", async () => {
      const { proof } = await signDocument(
        wrappedDocumentV2,
        SUPPORTED_SIGNING_ALGORITHM.Secp256k1VerificationKey2018,
        "did:ethr:0xE712878f6E8d5d4F9e87E10DA604F9cB564C9a89#controller",
        "0x497c85ed89f1874ba37532d1e33519aba15bd533cdcb90774cc497bfe3cde655"
      );
      expect(proof.length).toBe(1);
      expect(proof[0].proofPurpose).toBe("assertionMethod");
      expect(proof[0].type).toBe("OpenAttestationSignature2018");
      expect(proof[0].verificationMethod).toBe("did:ethr:0xE712878f6E8d5d4F9e87E10DA604F9cB564C9a89#controller");
      expect(proof[0].signature).toBe(
        "0xff0227ce8400a17a2d80073a95fd895f4fed0011954c90eef389bc618087a4b36ed958775420d122e9a6764c6ffe9d3302d4f45fb065d5e962c3572d3872f31a1b"
      );
    });

    it("should sign a document which was previously signed", async () => {
      const signedDocument = await signDocument(
        wrappedDocumentV2,
        SUPPORTED_SIGNING_ALGORITHM.Secp256k1VerificationKey2018,
        "did:ethr:0xb6De3744E1259e1aB692f5a277f053B79429c5a2#controller",
        "0x812269266b34d2919f737daf22db95f02642f8cdc0ca673bf3f701599f4971f5"
      );
      const { proof } = await signDocument(
        signedDocument,
        SUPPORTED_SIGNING_ALGORITHM.Secp256k1VerificationKey2018,
        "did:ethr:0xE712878f6E8d5d4F9e87E10DA604F9cB564C9a89#controller",
        "0x497c85ed89f1874ba37532d1e33519aba15bd533cdcb90774cc497bfe3cde655"
      );
      expect(proof.length).toBe(2);
      expect(proof[1].proofPurpose).toBe("assertionMethod");
      expect(proof[1].type).toBe("OpenAttestationSignature2018");
      expect(proof[1].verificationMethod).toBe("did:ethr:0xE712878f6E8d5d4F9e87E10DA604F9cB564C9a89#controller");
      expect(proof[1].signature).toBe(
        "0xff0227ce8400a17a2d80073a95fd895f4fed0011954c90eef389bc618087a4b36ed958775420d122e9a6764c6ffe9d3302d4f45fb065d5e962c3572d3872f31a1b"
      );
    });
  });

  describe("v3", () => {
    it("should sign a document", async () => {
      const { proof } = await signDocument(
        wrappedDocumentV3,
        SUPPORTED_SIGNING_ALGORITHM.Secp256k1VerificationKey2018,
        "did:ethr:0xE712878f6E8d5d4F9e87E10DA604F9cB564C9a89#controller",
        "0x497c85ed89f1874ba37532d1e33519aba15bd533cdcb90774cc497bfe3cde655"
      );
      expect(Object.keys(proof).length).toBe(9);
      expect(proof.key).toBe("did:ethr:0xE712878f6E8d5d4F9e87E10DA604F9cB564C9a89#controller");
      expect(proof.signature).toBe(
        "0x3ce62bb2d6a68f15fabe653dbb71edfaf1e2a00c71c98f71801f3a7438ae477a4cf3dbefaff9359b2d2b97473909ba4b19e9d2ac0c735cec926da0d1025af07b1c"
      );
    });

    it("should throw error if a document was previously signed", async () => {
      const signedDocument = await signDocument(
        wrappedDocumentV3,
        SUPPORTED_SIGNING_ALGORITHM.Secp256k1VerificationKey2018,
        "did:ethr:0xb6De3744E1259e1aB692f5a277f053B79429c5a2#controller",
        "0x812269266b34d2919f737daf22db95f02642f8cdc0ca673bf3f701599f4971f5"
      );

      await expect(
        signDocument(
          signedDocument,
          SUPPORTED_SIGNING_ALGORITHM.Secp256k1VerificationKey2018,
          "did:ethr:0xE712878f6E8d5d4F9e87E10DA604F9cB564C9a89#controller",
          "0x497c85ed89f1874ba37532d1e33519aba15bd533cdcb90774cc497bfe3cde655"
        )
      ).rejects.toThrowErrorMatchingInlineSnapshot(`"Document has been signed"`);
    });
  });
});

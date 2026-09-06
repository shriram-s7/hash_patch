package sample.aws;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;

public class KmsProtector {

    private final KmsClient client = KmsClient.builder().region(Region.US_EAST_1).build();

    public byte[] protect(byte[] plaintext) {
        EncryptResponse resp = client.encrypt(
            EncryptRequest.builder()
                .keyId("alias/protect")
                .plaintext(SdkBytes.fromByteArray(plaintext))
                .build());
        return resp.ciphertextBlob().asByteArray();
    }

    public byte[] unprotect(byte[] blob) {
        DecryptResponse resp = client.decrypt(
            DecryptRequest.builder()
                .keyId("alias/protect")
                .ciphertextBlob(SdkBytes.fromByteArray(blob))
                .build());
        return resp.plaintext().asByteArray();
    }
}
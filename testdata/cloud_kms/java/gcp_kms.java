package sample.gcp;

import com.google.cloud.kms.v1.DecryptRequest;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;

public class GcpKeyHelper {

    public byte[] unseal(String name, byte[] blob) {
        try (KeyManagementServiceClient kmsClient = KeyManagementServiceClient.create()) {
            DecryptResponse response = kmsClient.decrypt(
                DecryptRequest.newBuilder()
                    .setName(name)
                    .setCiphertext(ByteString.copyFrom(blob))
                    .build());
            return response.getPlaintext().toByteArray();
        }
    }
}
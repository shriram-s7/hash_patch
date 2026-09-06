package sample.neg;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

public class ImportOnly {

    KmsClient buildClient() {
        return KmsClient.builder().region(Region.US_WEST_2).build();
    }
}
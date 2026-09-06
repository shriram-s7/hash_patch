package sample.neg;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

public class ConstructedUnused {

    void init() {
        KmsClient unused = KmsClient.builder().region(Region.US_EAST_1).build();
        int x = 1;
    }
}
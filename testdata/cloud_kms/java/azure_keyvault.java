package sample.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.EncryptResult;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.azure.security.keyvault.keys.models.KeyType;
import com.azure.security.keyvault.keys.models.KeyVaultKey;

public class AzureKeyHelper {

    private final String vaultUrl;
    private final TokenCredential credential;

    public AzureKeyHelper(String vaultUrl, TokenCredential credential) {
        this.vaultUrl = vaultUrl;
        this.credential = credential;
    }

    public byte[] protect(String keyUrl, byte[] plaintext) {
        CryptographyClient cryptoClient = new CryptographyClient(keyUrl, credential);
        EncryptResult enc = cryptoClient.encrypt(EncryptionAlgorithm.RSA_OAEP, plaintext);
        return enc.getCiphertext();
    }

    public KeyVaultKey createPolicyKey() {
        KeyClient keyClient = new KeyClient(vaultUrl, credential);
        return keyClient.createKey("crypto-policy-key", KeyType.RSA_HSM);
    }
}
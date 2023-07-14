package com.github.starlightsoftware.hmacsha;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.models.credential.PasswordCredentialModel;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author <a href="mailto:mark@starlight.software">Mark Lanning</a>
 * @tester Tested against https://dinochiesa.github.io/hmachash/index.html
*/
class HmacShaPasswordHashProviderTest {    

    private final String secretKey = "SecretKey1234567890!";
    
    private final String rawPassword = "Password!";
    private final String salt = "S@lt!";

    // ================================================================================
    // Raw Password: Password!
    //         Salt: S@lt!
    // ================================================================================
    //    SHA1 Hash: AWJOTipDJuZL6GFfxDe6i4DFHiM=
    //  SHA256 Hash: UKrbynnoL4jYaowq+AagxnDxy0XxtLpU5W8HEV5qc0A=
    //  SHA384 Hash: CrKEdxPWuUbJfLG33cnt1fSxnDPra6pmPTN0FFX9HNx88RBGDiHmINvl/1eIJk3c
    //  SHA512 Hash: d1TtARS7EoO4jvR8nMGCT4eNga7dTSYZp0UOXQ2fzP6w9pJ2ompklpx71epqHxDj12WrdAHT/2Nk4Q7fVBOpzw==
    // ================================================================================

    @Test
    @DisplayName("Should hash the password successfully")
    void sha1Test() 
    {   
        hashTest("HmacSha1", "HmacSHA1", "AWJOTipDJuZL6GFfxDe6i4DFHiM=");
    }

    @Test
    @DisplayName("Should hash the password successfully")
    void sha256Test() 
    {   
        hashTest("HmacSha256", "HmacSHA256", "UKrbynnoL4jYaowq+AagxnDxy0XxtLpU5W8HEV5qc0A=");
    }

    @Test
    @DisplayName("Should hash the password successfully")
    void sha384Test() 
    {   
        hashTest("HmacSha384", "HmacSHA384", "CrKEdxPWuUbJfLG33cnt1fSxnDPra6pmPTN0FFX9HNx88RBGDiHmINvl/1eIJk3c");
    }

    @Test
    @DisplayName("Should hash the password successfully")
    void sha512Test() 
    {        
        hashTest("HmacSha512", "HmacSHA512", "d1TtARS7EoO4jvR8nMGCT4eNga7dTSYZp0UOXQ2fzP6w9pJ2ompklpx71epqHxDj12WrdAHT/2Nk4Q7fVBOpzw==");
    }
    
    void hashTest(string providerId, String hmacAlgorithm, String expectedHash) {
        
        final HmacShaPasswordHashProvider provider = new HmacShaPasswordHashProvider(providerId, hmacAlgorithm, this.secretKey);
        String hashedPassword = provider.encode(this.rawPassword, this.salt);

        PasswordCredentialModel model = PasswordCredentialModel.createFromValues(providerId, new byte[0], 1, hashedPassword);

        assertNotNull(hashedPassword);
        assertTrue(provider.verify(rawPassword, model));

        // verify that the expected hash matches the computed one.. otherwise we aren't matching expected hashes that were imported.
        assertTrue(hashedPassword.equals(expectedHash));        
    }   
}
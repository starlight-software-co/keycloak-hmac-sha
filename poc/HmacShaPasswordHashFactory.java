import java.util.Base64;
import java.nio.charset.StandardCharsets;

import java.security.NoSuchAlgorithmException; 
import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HmacShaPasswordHashFactory 
{    
    private final String hmacAlgorithm;
    private final String secretKey;
    
    public HmacShaPasswordHashFactory(String hmacAlgorithm, String secretKey)
    {        
        this.hmacAlgorithm = hmacAlgorithm;
        this.secretKey = secretKey;
    }
    
    public String generate(String rawPassword, String salt) 
    {
        String salted = rawPassword + salt;
        final byte[] saltedBytes = salted.getBytes(StandardCharsets.UTF_8);

        try
        {
            final byte[] byteKey = this.secretKey.getBytes(StandardCharsets.UTF_8);

            Mac hashFactory = Mac.getInstance(this.hmacAlgorithm);
            SecretKeySpec keySpec = new SecretKeySpec(byteKey, this.hmacAlgorithm);
            hashFactory.init(keySpec);
            
            // do the hash with the pwd + salt value
            byte[] macData = hashFactory.doFinal(saltedBytes);

            // Can either base64 encode or put it right into hex
            return Base64.getEncoder().encodeToString(macData);  
            
        } 
        catch (InvalidKeyException | NoSuchAlgorithmException e) 
        {                                         
            return "==ERROR: " + e.getMessage();
        }
    }   
}

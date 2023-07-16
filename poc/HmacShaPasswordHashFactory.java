import java.util.Base64;
import java.nio.charset.StandardCharsets;

import java.security.NoSuchAlgorithmException; 
import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HmacShaPasswordHashFactory 
{    
    private final String hmacAlgorithm;
    private final String algorithmKey;
    
    public HmacShaPasswordHashFactory(String hmacAlgorithm, String algorithmKey)
    {        
        this.hmacAlgorithm = hmacAlgorithm;
        this.algorithmKey = algorithmKey;
    }
    
    public String generate(String rawPassword, String salt) 
    {
        final byte[] rawPasswordBytes = rawPassword.getBytes(StandardCharsets.UTF_8);
        final byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);

        byte[] saltedPasswordBytes = Concat(rawPasswordBytes, saltBytes);      

        try
        {
            final byte[] byteKey = this.algorithmKey.getBytes(StandardCharsets.UTF_8);

            Mac hashFactory = Mac.getInstance(this.hmacAlgorithm);
            SecretKeySpec keySpec = new SecretKeySpec(byteKey, this.hmacAlgorithm);
            hashFactory.init(keySpec);
            
            // do the hash with the pwd + salt value
            byte[] macData = hashFactory.doFinal(saltedPasswordBytes);

            // Can either base64 encode or put it right into hex
            return Base64.getEncoder().encodeToString(macData);  
            
        } 
        catch (InvalidKeyException | NoSuchAlgorithmException e) 
        {                                         
            return "==ERROR: " + e.getMessage();
        }
    }   

    public byte[] Concat(byte[] arrayA, byte[] arrayB)
    {        
        byte[] arrayC = new byte[arrayA.length + arrayB.length];
        System.arraycopy(arrayA, 0, arrayC, 0, arrayA.length);
        System.arraycopy(arrayB, 0, arrayC, arrayA.length, arrayB.length);

        return arrayC;
    }
}

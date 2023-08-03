package com.github.starlightsoftware.keycloak.hmacsha;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.common.util.Base64;
import org.keycloak.Config;

import org.jboss.logging.Logger;
import java.io.IOException;

import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;

import java.security.NoSuchAlgorithmException; 
import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author <a href="mailto:info@starlight.software">Mark Lanning</a>
 * @see https://github.com/keycloak/keycloak/tree/main/server-spi-private/src/main/java/org/keycloak/credential/hash
 * @see https://github.com/leroyguillaume/keycloak-bcrypt
*/
public class HmacShaPasswordHashProvider implements PasswordHashProvider 
{   
    protected static Logger log = Logger.getLogger(HmacShaPasswordHashProvider.class);

    private final String providerId;
    private final String hmacAlgorithm;
    private final String secretKey;
    private final Boolean isRehash;  // this algorithm is out of date we want to rehash the values to the standard algorithm
    
    public HmacShaPasswordHashProvider(String providerId, String hmacAlgorithm, String secretKey, boolean isRehash)
    {
        this.providerId = providerId;
        this.hmacAlgorithm = hmacAlgorithm;
        this.secretKey = secretKey;
        this.isRehash = isRehash;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) 
    {
        return providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations)
    {  
        if (iterations <= 0) {
            iterations = 1; // technically there are no iterations
        } 

        byte[] saltBytes = generateSaltBytes();
        String salt = Base64.encodeBytes(saltBytes);

        String encodedPassword = encode(rawPassword, salt);

        return PasswordCredentialModel.createFromValues(providerId, saltBytes, iterations, encodedPassword);
    }

    @Override
    public String encode(String rawPassword, int iterations) 
    {                
        if (iterations <= 0) {
            iterations = 1; // technically there are no iterations
        } 
        
        byte[] saltBytes = generateSaltBytes();
        String salt = Base64.encodeBytes(saltBytes);

        return encode(rawPassword, salt);
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) 
    {
        log.debugf("HmacShaPasswordHashProvider.verify()");
        String existingHash = credential.getPasswordSecretData().getValue();

        byte[] existingSaltBytes = credential.getPasswordSecretData().getSalt();    //returns as byte array
        String existingSalt = new String(existingSaltBytes);
        
        // calculate and compare        
        String rawPasswordHash = encode(rawPassword, existingSalt);
        if(!rawPasswordHash.equals(existingHash))
        {
            log.debugf("Hash Mismatch:");
            log.debugf("   Raw Hash: %s", rawPasswordHash);
            log.debugf("Stored Hash: %s", existingHash);
            log.debugf("Stored Salt: %s", existingSalt);            
            return false;
        }

        // since we now know the right password, use it to rehash the password hash with newer algorithm
        if(isRehash)
        {
            rehashPassword(rawPassword);
        }

        return true;
    }

    @Override
    public void close() 
    {
        //nothing
    }

    
    private static void rehashPassword(String rawPassword)
    {
        log.debugf("Rehashing Password.");

        // default algorithm specifics (TODO: get default hash algorithm from realm password policy)
        String providerId = "pbkdf2-sha256";
        String algorithmId = "PBKDF2WithHmacSHA256";
        int defaultIterations = 27500;

        byte[] saltBytes = generateSaltBytes();
        
        var hashAlgorithm = new org.keycloak.credential.hash.Pbkdf2PasswordHashProvider(providerId, algorithmId, defaultIterations, 0, 256);
        String encodedPassword = hashAlgorithm.encode(rawPassword, defaultIterations);

        PasswordCredentialModel.createFromValues(algorithmId, saltBytes, defaultIterations, encodedPassword);
    }
    
    
    private static byte[] generateSaltBytes() 
    {
        SecureRandom random = new SecureRandom();
        byte saltBytes[] = new byte[12];
        random.nextBytes(saltBytes);
        
        return saltBytes;
    }

    public String encode(String rawPassword, String salt) 
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
            return Base64.encodeBytes(macData);  
            
        } 
        catch (InvalidKeyException | NoSuchAlgorithmException e) 
        {                                         
            return "==ERROR: " + e.getMessage();
        }
    }  


    public static String GetAlgorithmKey(Config.Scope config)
    {        
        var algorithmKey64 = config.get("key");
        if(algorithmKey64 == null){ return null; }

        try
        {
            // de-base64 the string 
            return new String(Base64.decode(algorithmKey64));        
        } 
        catch (IOException e)
        {
            Logger log = Logger.getLogger(HmacShaPasswordHashProvider.class);

            log.error("Unable to base64 decode algorithm key from configuration.");
            log.error(e);

            return null;
        }
    }    
}
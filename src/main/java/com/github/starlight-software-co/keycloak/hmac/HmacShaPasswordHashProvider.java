package com.github.starlightsoftware.hmacsha;

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
    
    public HmacShaPasswordHashProvider(String providerId, String hmacAlgorithm, String secretKey)
    {
        this.providerId = providerId;
        this.hmacAlgorithm = hmacAlgorithm;
        this.secretKey = secretKey;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) 
    {
        //TODO: Check if secret key is actually defined?

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
        
        log.infof("HmacShaPasswordHashProvider.verify()");
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
        
        return true;
    }

    @Override
    public void close() 
    {
        //nothing
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
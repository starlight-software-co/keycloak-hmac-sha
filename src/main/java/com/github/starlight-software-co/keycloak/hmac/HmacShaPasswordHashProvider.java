package com.github.starlightsoftware.hmacsha;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.util.Base64;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;

import java.security.NoSuchAlgorithmException; 
import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author <a href="mailto:mark@starlight.software">Mark Lanning</a>
 * @see https://github.com/keycloak/keycloak/tree/main/server-spi-private/src/main/java/org/keycloak/credential/hash
 * @see https://github.com/leroyguillaume/keycloak-bcrypt
*/
public class HmacShaPasswordHashProvider implements PasswordHashProvider 
{   
    private final String providerId;
    private final String hmacAlgorithm;
    private final String secretKey;
    
    public HmacSha1PasswordHashProvider(String providerId, String hmacAlgorithm, String secretKey)
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

        String salt = generateSaltBase64();

        String encodedPassword = encode(rawPassword, salt);

        return PasswordCredentialModel.createFromValues(providerId, salt, iterations, encodedPassword);
    }

    @Override
    public String encode(String rawPassword, int iterations) 
    {                
        if (iterations <= 0) {
            iterations = 1; // technically there are no iterations
        } 
        
        String salt = generateSaltBase64();

        return encode(rawPassword, salt);
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) 
    {      
        String existingHash = credential.getPasswordSecretData().getValue();

        byte[] existingSaltBytes = credential.getPasswordSecretData().getSalt();    //returns as byte array
        String existingSalt = Base64.getEncoder().encodeToString(existingSaltBytes);
                
        // calculate and compare
        String rawPasswordHash = encode(rawPassword, salt);

        return rawPasswordHash.equals(existingHash);
    }

    @Override
    public void close() 
    {
        //nothing
    }
    
    
    private static String generateSaltBase64() 
    {
        SecureRandom random = new SecureRandom();
        byte saltBytes[] = new byte[12];
        random.nextBytes(saltBytes);
        
        return Base64.getEncoder().encodeToString(saltBytes);
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
            return Base64.getEncoder().encodeToString(macData);  
            
        } 
        catch (InvalidKeyException | NoSuchAlgorithmException e) 
        {                                         
            return "==ERROR: " + e.getMessage();
        }
    }  
}
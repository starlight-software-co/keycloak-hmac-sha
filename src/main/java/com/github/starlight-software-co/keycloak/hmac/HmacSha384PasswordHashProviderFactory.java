package com.github.starlightsoftware.hmacsha;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderFactory;

/**
 * @author <a href="mailto:mark@lannings.org">Mark Lanning</a>
 */
public class HmacSha384PasswordHashProviderFactory implements PasswordHashProviderFactory {
    
    public static final String ID = "HmacSha384";
    public static final String ALGORITHM = "HmacSHA384";
        
    private String secretKey;

    @Override
    public PasswordHashProvider create(KeycloakSession session) 
    {
        return new HmacShaPasswordHashProvider(ID, ALGORITHM, this.secretKey);
    }

    @Override
    public void init(Config.Scope config) 
    {        
        this.secretKey = config.get("secretKey");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) 
    {
        //nothing
    }

    @Override
    public String getId() 
    {
        return ID;
    }

    @Override
    public void close() 
    {   
        //nothing
    }
}
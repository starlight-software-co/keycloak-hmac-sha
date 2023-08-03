// package com.github.starlightsoftware.hmacsha;

// import org.keycloak.Config;
// import org.keycloak.credential.hash.PasswordHashProvider;
// import org.keycloak.credential.hash.PasswordHashProviderFactory;
// import org.keycloak.models.KeycloakSession;
// import org.keycloak.models.KeycloakSessionFactory;
// import org.keycloak.provider.ProviderFactory;

// import org.jboss.logging.Logger;

// /**
//  * @author <a href="mailto:info@starlight.software">Mark Lanning</a>
//  */
// public class HmacSha256PasswordHashProviderFactory implements PasswordHashProviderFactory {
    
//     protected static Logger log = Logger.getLogger(HmacSha256PasswordHashProviderFactory.class);

//     public static final String ID = "hmac-sha256";
//     public static final String ALGORITHM = "HmacSHA256";
        
//     private String algorithmKey;

//     @Override
//     public PasswordHashProvider create(KeycloakSession session) 
//     {
//         return new HmacShaPasswordHashProvider(ID, ALGORITHM, this.algorithmKey);
//     }

//     @Override
//     public void init(Config.Scope config) 
//     {        
//         String key = HmacShaPasswordHashProvider.GetAlgorithmKey(config);
//         if(key != null)
//         {
//             log.info("Key found from config.");
//             this.algorithmKey = key;            
//         }
//         else
//         {
//             log.warn("Unable to find hmac-sha512 initialization key from config. Falling back to static generated key.");

//             this.algorithmKey = "P@ssw0rdsAreHard!gshLgK#&tt4z5^Zr!5GHd6t4cVhrB^cXJxktenoAZia%Wg";  //Random Password generated 
            
//             return;
//         }
//     }

//     @Override
//     public void postInit(KeycloakSessionFactory factory) 
//     {
//         //nothing
//     }

//     @Override
//     public String getId() 
//     {
//         return ID;
//     }

//     @Override
//     public void close() 
//     {   
//         //nothing
//     }
// }
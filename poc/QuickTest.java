public class QuickTest {
    
    public static void main (String[] args) {
           
        final String secretKey = "SecretKey!";

        final String rawPassword = "Password!";
        final String salt = "uQsmZO8EZq";


        //System.out.print("Secret Key: ");
        //System.out.println(secretKey);
        
        System.out.println("================================================================================");

        System.out.print("Raw Password: ");
        System.out.println(rawPassword);

        System.out.print("        Salt: ");
        System.out.println(salt);
        
        System.out.println("================================================================================");
        
        // // HmacMD5
        // System.out.print("    MD5 Hash: ");
        // var hashProviderMd5 = new HmacShaPasswordHashFactory("HmacMD5", secretKey);
        // System.out.println(hashProviderMd5.generate(rawPassword, salt));
        
        // HmacSHA1
        System.out.print("   SHA1 Hash: ");
        var hashProvider1 = new HmacShaPasswordHashFactory("HmacSHA1", secretKey);
        System.out.println(hashProvider1.generate(rawPassword, salt));        

        // HmacSHA256        
        System.out.print(" SHA256 Hash: ");
        var hashProvider256 = new HmacShaPasswordHashFactory("HmacSHA256", secretKey);
        System.out.println(hashProvider256.generate(rawPassword, salt));

        // HmacSHA384
        System.out.print(" SHA384 Hash: ");
        var hashProvider384 = new HmacShaPasswordHashFactory("HmacSHA384", secretKey);
        System.out.println(hashProvider384.generate(rawPassword, salt));        
        
        // HmacSHA512
        System.out.print(" SHA512 Hash: ");
        var hashProvider512 = new HmacShaPasswordHashFactory("HmacSHA512", secretKey);
        System.out.println(hashProvider512.generate(rawPassword, salt));     
        
        System.out.println("================================================================================");
    }  
}

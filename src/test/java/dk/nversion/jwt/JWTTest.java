/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package dk.nversion.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author tlb
 */
public class JWTTest {
    
    public JWTTest() {
    }
    
    /**
     * Test of JWT.encode
     */
    @Test
    public void testJWTEncode() {
        System.out.println("encode");
        try {
            JWT token = new JWT(Algorithm.HS256, "12345678");
        
            token.setId("1"); // TODO generate random number
            token.setIssuer("http://localhost/oauth/");
            token.setAudience("http://localhost/service");
            token.setIssuedAt(1426296045);
            token.setNotBefore(1426295995); // 5 minutes before issued at
            token.setExpires(1426296645); // 10 minutes after issued at            
            token.setSubject("g48391@nordea.com");

            String result = token.encode();
            String expResult = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxIiwiaWF0IjoxNDI2Mjk2MDQ1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0L29hdXRoLyIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Qvc2VydmljZSIsImV4cCI6MTQyNjI5NjY0NSwibmJmIjoxNDI2Mjk1OTk1LCJzdWIiOiJnNDgzOTFAbm9yZGVhLmNvbSJ9.AVaEoikqCla-dE-Gj1o3fZj5ZYGnzEE4l7zCXQD9BE4";
            assertEquals(expResult, result);
        
        } catch(JWTException | JsonProcessingException | NoSuchAlgorithmException | InvalidKeyException ex) {
            fail("Failed with exception");
        }
    }
    
    /**
     * Test of JWT construction and validation
     */
    @Test
    public void testJWTDecode() {
        try {
            System.out.println("decode");
            JWT token = new JWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxIiwiaWF0IjoxNDI2Mjk2MDQ1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0L29hdXRoLyIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Qvc2VydmljZSIsImV4cCI6MTQyNjI5NjY0NSwibmJmIjoxNDI2Mjk1OTk1LCJzdWIiOiJnNDgzOTFAbm9yZGVhLmNvbSJ9.AVaEoikqCla-dE-Gj1o3fZj5ZYGnzEE4l7zCXQD9BE4", "12345678");
        } catch (JWTException | IOException | InvalidKeyException | NoSuchAlgorithmException ex) {
            fail("Failed with exception");
        }
    }    
}

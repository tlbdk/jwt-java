/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package dk.nversion.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import static dk.nversion.jwt.CryptoUtils.loadCertificate;
import static dk.nversion.jwt.CryptoUtils.loadPrivateKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
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
     * Test of JWT encode shared key
     */
    @Test
    public void testJWTEncodeSharedKey() {
        System.out.println("encode");
        try {
            JWT token = new JWT(Algorithm.HS256, "12345678");
        
            token.setId("1"); // TODO generate random number
            token.setIssuer("http://localhost/oauth/");
            token.setAudience("http://localhost/service");
            token.setIssuedAt(1426296045);
            token.setNotBefore(1); // 1 January 1970
            token.setExpires(2147483647); // 03:14:07 UTC on Tuesday, 19 January 2038
            token.setSubject("tlb@nversion.dk");

            String result = token.encode();
            String expResult = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxIiwiaWF0IjoxNDI2Mjk2MDQ1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0L29hdXRoLyIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Qvc2VydmljZSIsImV4cCI6MjE0NzQ4MzY0NywibmJmIjoxLCJzdWIiOiJ0bGJAbnZlcnNpb24uZGsifQ.0kE6nOybDA-HBxgsmQ5PISsH8cm_lZi_nI8-cPj_Tkg";
            assertEquals(expResult, result);
        
        } catch(JWTException | JsonProcessingException | NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            fail("Failed with exception");
        }
    }
    
     /**
     * Test of JWT encode private key
     */
    @Test
    public void testJWTEncodePrivateKey() throws CertificateException {        
        System.out.println("encode");
        
        try {
            // Load private key
            String privatekeyfile = getClass().getClassLoader().getResource("example.org.pem").getFile();
            PrivateKey privkey = loadPrivateKey(privatekeyfile);
            JWT token = new JWT(Algorithm.RS256, privkey);
        
            long unixtime = Instant.now().getEpochSecond();
            
            token.setId("1"); // TODO generate random number
            token.setIssuer("http://localhost/oauth/");
            token.setAudience("http://localhost/service");
            token.setIssuedAt(unixtime);
            token.setNotBefore(unixtime - 5 * 60); // 5 minutes before issued at
            token.setExpires(unixtime + 10 * 60); // 10 minutes after issued at            
            token.setSubject("tlb@nversion.dk");

            String result = token.encode();
            
            String certificatefile = getClass().getClassLoader().getResource("example.org.crt").getFile();
            PublicKey pubkey = loadCertificate(certificatefile);
            
            JWT token2 = new JWT(result, pubkey, "http://localhost/service");
            
            System.out.println("stuff");
        
        } catch(IOException | JWTException | NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | SignatureException ex) {
            fail("Failed with exception");
        }
    }
    
    /**
     * Test of JWT construction and validation
     */
    @Test
    public void testJWTDecodeSharedKey() {
        try {
            System.out.println("decode");
            JWT token = new JWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxIiwiaWF0IjoxNDI2Mjk2MDQ1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0L29hdXRoLyIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Qvc2VydmljZSIsImV4cCI6MjE0NzQ4MzY0NywibmJmIjoxLCJzdWIiOiJnNDgzOTFAbm9yZGVhLmNvbSJ9.u1KzSZdz6n-a5RJ4Cm-o6wMZ2w3s9TApGqOoAULBbjA", "12345678", "http://localhost/service");
            
        } catch (JWTException | IOException | InvalidKeyException | NoSuchAlgorithmException | SignatureException ex) {
            fail("Failed with exception");
        }
    }
    
    /**
     * Test of JWT construction and validation speed
     */
    @Test
    public void testJWTDecodeSharedKeySpeed() {
        try {
            int i;
            System.out.println("decode speed");
            
            // Warmup
            for (i = 0; i < 1000; i++) {
                JWT token = new JWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxIiwiaWF0IjoxNDI2Mjk2MDQ1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0L29hdXRoLyIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Qvc2VydmljZSIsImV4cCI6MjE0NzQ4MzY0NywibmJmIjoxLCJzdWIiOiJnNDgzOTFAbm9yZGVhLmNvbSJ9.u1KzSZdz6n-a5RJ4Cm-o6wMZ2w3s9TApGqOoAULBbjA", "12345678", "http://localhost/service");
            }
            
            long startTime = System.currentTimeMillis();
            for (i = 0; i < 10000; i++) {
                JWT token = new JWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxIiwiaWF0IjoxNDI2Mjk2MDQ1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0L29hdXRoLyIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Qvc2VydmljZSIsImV4cCI6MjE0NzQ4MzY0NywibmJmIjoxLCJzdWIiOiJnNDgzOTFAbm9yZGVhLmNvbSJ9.u1KzSZdz6n-a5RJ4Cm-o6wMZ2w3s9TApGqOoAULBbjA", "12345678", "http://localhost/service");
            }
            long endTime = System.currentTimeMillis();
            long totalTime = endTime - startTime;
            System.out.println("time taken for shared key: " + totalTime + " ms, " +  (i / (totalTime / 1000.0)) + " i/s");
            
        } catch (JWTException | IOException | InvalidKeyException | NoSuchAlgorithmException ex) {
            fail("Failed with exception");
        } catch (SignatureException ex) {
            Logger.getLogger(JWTTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Test of JWT construction and validation speed
     */
    @Test
    public void testJWTDecodePublicKeySpeed() {
        try {
            int i;
            System.out.println("decode speed");
            
            // Load private key
            String privatekeyfile = getClass().getClassLoader().getResource("example.org.pem").getFile();
            PrivateKey privkey = loadPrivateKey(privatekeyfile);
            JWT token = new JWT(Algorithm.RS256, privkey);
        
            long unixtime = Instant.now().getEpochSecond();
            
            token.setId("1"); // TODO generate random number
            token.setIssuer("http://localhost/oauth/");
            token.setAudience("http://localhost/service");
            token.setIssuedAt(unixtime);
            token.setNotBefore(unixtime - 5 * 60); // 5 minutes before issued at
            token.setExpires(unixtime + 10 * 60); // 10 minutes after issued at            
            token.setSubject("tlb@nversion.dk");

            String result = token.encode();
            
            String certificatefile = getClass().getClassLoader().getResource("example.org.crt").getFile();
            PublicKey pubkey = loadCertificate(certificatefile);
            
            // Warmup
            for (i = 0; i < 1000; i++) {
                JWT token2 = new JWT(result, pubkey, "http://localhost/service");
            }
            
            long startTime = System.currentTimeMillis();
            for (i = 0; i < 10000; i++) {
                JWT token2 = new JWT(result, pubkey, "http://localhost/service");
            }
            long endTime = System.currentTimeMillis();
            long totalTime = endTime - startTime;
            System.out.println("time taken for pubkey: " + totalTime + " ms, " +  (i / (totalTime / 1000.0)) + " i/s");
            
        } catch (JWTException | IOException | InvalidKeyException | NoSuchAlgorithmException ex) {
            fail("Failed with exception");
        } catch (SignatureException | InvalidKeySpecException | CertificateException ex) {
            Logger.getLogger(JWTTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}

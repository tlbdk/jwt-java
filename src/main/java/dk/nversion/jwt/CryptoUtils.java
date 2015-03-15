/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package dk.nversion.jwt;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author tlb
 */
public class CryptoUtils {
    
    public static PrivateKey loadPrivateKey(String filename) throws FileNotFoundException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        PrivateKey key = null;
        InputStream is = null;
        try {
            is = new FileInputStream(filename);
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            
            String line;
            while((line = br.readLine()) != null){
                if (!inKey) {
                    if (line.startsWith("-----BEGIN PRIVATE KEY-----")) {
                        inKey = true;
                    }
                } else {
                    if (line.startsWith("-----END PRIVATE KEY-----")) {
                        break;
                    }
                    builder.append(line);
                }
            }
            
            byte[] encoded = Base64.decodeBase64(builder.toString());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            key = kf.generatePrivate(keySpec);
        
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException ex) {
                    // Ignore
                }
            }
        }
        return key;
    }
    
    public static PublicKey loadCertificate(String filename) throws FileNotFoundException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException {
        PublicKey key = null;
        InputStream is = null;
        try {
            is = new FileInputStream(filename);
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            
            String line;
            while((line = br.readLine()) != null){
                if (!inKey) {
                    if (line.startsWith("-----BEGIN CERTIFICATE-----")) {
                        inKey = true;
                    }
                } else {
                    if (line.startsWith("-----END CERTIFICATE-----")) {
                        break;
                    }
                    builder.append(line);
                }
            }
            
            if(builder.length() == 0) {
                throw new CertificateException("Did not find a certificate in the file");
            }
            
            byte[] encoded = Base64.decodeBase64(builder.toString());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
            key = certificate.getPublicKey();

        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException ex) {
                    // Ignore
                }
            }
        }
        return key;
    }
}

package dk.nversion.jwt;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

public class JWT {    
    private static class Header {
        @JsonProperty("alg")
        private Algorithm algorithm;
        @JsonProperty("typ")
        private final String type = "JWT";
    }
    
    private static class Body {
        @JsonProperty("jti")
        private String id;
        @JsonProperty("iat")
        private long issuedAt;
        @JsonProperty("iss")
        private String issuer;
        @JsonProperty("aud")
        private String audience;
        @JsonProperty("exp")
        private long expires = -1;
        @JsonProperty("nbf")
        private long notBefore = -1;
        @JsonProperty("sub")
        private String subject;
    }

    private Header header;
    private Body body;
    
    private byte[] sharedkey;
    private PrivateKey privatekey;
    
    private int notBeforeMax = 600;
    private int expiresMax = 6000;
    
    public JWT() {
        this.body = new Body();
        this.header = new Header();
        
    }
    
    public JWT(Algorithm algorithm, String key) throws JWTException {
        this(algorithm, key.getBytes(StandardCharsets.UTF_8));
    }
    
    public JWT(Algorithm algorithm, byte[] key) throws JWTException {
        if(algorithm.name().startsWith("RS")) {
           throw new JWTException("This algorithm needs a X509 Certificate");
        }
        if(key.length == 0) {
             throw new JWTException("Key should be longer than zero");
        }
        
        this.body = new Body();
        this.header = new Header();
        this.header.algorithm = algorithm;
        this.sharedkey = key;
    }
    
    public JWT(Algorithm algorithm, PrivateKey privatekey) throws JWTException {
        if(algorithm.name().startsWith("HS")) {
            throw new JWTException("This algorithm needs a shared key");
        }
        if(privatekey == null) {
             throw new JWTException("Private key can not be null");
        }
        
        this.body = new Body();
        this.header = new Header();
        this.header.algorithm = algorithm;
        this.privatekey = privatekey;
    }
    
    public JWT(String token, String key, String audience) throws JWTException, IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        this(token, key.getBytes(StandardCharsets.UTF_8), null, audience);
    }
    
    public JWT(String token, byte [] key, String audience) throws JWTException, IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        this(token, key, null, audience);
    }
    
    public JWT(String token, PublicKey key, String audience) throws JWTException, IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        this(token, null, key, audience);
    }
    
    private JWT(String token, byte [] sharedkey, PublicKey publickey, String audience) throws JWTException, IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        if(StringUtils.countMatches(token, ".") != 2) {
            throw new JWTException("Not a valid JWT token as it does not contain two dots");
        }
        
        int header_offset = token.indexOf('.');
        int body_offset = token.indexOf('.', header_offset + 1);
        
        ObjectMapper mapper = new ObjectMapper();

        this.header = mapper.readValue(Base64.decodeBase64(token.substring(0, header_offset)), Header.class);
        this.body = mapper.readValue(Base64.decodeBase64(token.substring(header_offset + 1, body_offset)), Body.class);
        byte[] signature_bytes = Base64.decodeBase64(token.substring(body_offset + 1, token.length()));
        byte[] header_body_bytes = Arrays.copyOfRange(token.getBytes(StandardCharsets.UTF_8), 0, body_offset);
        
        switch (header.algorithm) {
            case HS256:
            case HS384:
            case HS512: {
                // Calculate the signature
                Mac mac = Mac.getInstance(header.algorithm.getValue());
                mac.init(new SecretKeySpec(sharedkey, header.algorithm.getValue()));
                byte[] calculated_signature_bytes = mac.doFinal(header_body_bytes);
                // Validate signature with a time safe comparison
                if(!MessageDigest.isEqual(signature_bytes, calculated_signature_bytes)) {
                    throw new JWTException("Signature validation failed");
                }
                break;
            }
            case RS256:
            case RS384:
            case RS512: {
                Signature signature = Signature.getInstance(header.algorithm.getValue());
                signature.initVerify(publickey);
                signature.update(header_body_bytes);
                if(!signature.verify(signature_bytes)) {
                    throw new JWTException("Signature validation failed");
                }
                break;
            }
            default: {
                throw new JWTException("Unsupported signing method");
            }
        }

        // Validate that this token was intented for us
        if(audience != null && (body.audience == null || !audience.equals(body.audience))) {
            throw new JWTException("Audience not set in token or did not match");
        }
        
        // Validate with have both expires and notbefore set
        if(body.notBefore == -1 || body.expires == -1) {
            throw new JWTException("The token needs to have both a nbf and exp to be accepted");
        }
        
        long unixtime = Instant.now().getEpochSecond();
        // Validate that the token is valid
        if(body.notBefore >= unixtime) {
            throw new JWTException("Token is not valid yet");
        }
        
        // Validate that the token has not expired
        if(body.expires <= unixtime) {
            throw new JWTException("Token has expired");
        }
    }
    
    public String encode() throws JWTException, JsonProcessingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            // Convert header and body to Base64URL encoded JSON bytes
            ObjectMapper mapper = new ObjectMapper();
            byte[] header_bytes = Base64.encodeBase64URLSafe(mapper.writeValueAsBytes(header));
            byte[] body_bytes = Base64.encodeBase64URLSafe(mapper.writeValueAsBytes(body));
            
            // Create header.body token bytes
            byte[] header_body_bytes = new byte[header_bytes.length + 1 + body_bytes.length];
            System.arraycopy(header_bytes, 0, header_body_bytes, 0, header_bytes.length);
            header_body_bytes[header_bytes.length] = (byte)46; // .
            System.arraycopy(body_bytes, 0, header_body_bytes, header_bytes.length + 1, body_bytes.length);
            
            // Get Base64URL encoded signature bytes for header_body_bytes 
            byte[] signature_bytes;
            switch (header.algorithm) {
                case HS256:
                case HS384:
                case HS512: {
                    Mac mac = Mac.getInstance(header.algorithm.getValue());
                    mac.init(new SecretKeySpec(sharedkey, header.algorithm.getValue()));
                    signature_bytes = Base64.encodeBase64URLSafe(mac.doFinal(header_body_bytes));
                    break;
                }
                case RS256:
                case RS384:
                case RS512: {
                    Signature signature = Signature.getInstance(header.algorithm.getValue());
                    signature.initSign(privatekey);
                    signature.update(header_body_bytes);
                    signature_bytes = Base64.encodeBase64URLSafe(signature.sign());
                    break;
                }
                default: {
                    throw new JWTException("Unsupported signing method");
                }
            }
            
            // Create final token : header.body.signature
            byte[] token = new byte[header_body_bytes.length + 1 + signature_bytes.length];
            System.arraycopy(header_body_bytes, 0, token, 0, header_body_bytes.length);
            token[header_body_bytes.length] = (byte)46; // .
            System.arraycopy(signature_bytes, 0, token, header_body_bytes.length + 1, signature_bytes.length);

            // Create final string
            return new String(token, StandardCharsets.UTF_8);
    }
    
    /**
     * @return the algorithm
     */
    public Algorithm getAlgorithm() {
        return header.algorithm;
    }

    /**
     * @param algorithm the algorithm to set
     */
    public void setAlgorithm(Algorithm algorithm) {
        this.header.algorithm = algorithm;
    }

    /**
     * @return the audience
     */
    public String getAudience() {
        return body.audience;
    }

    /**
     * @param audience the audience to set
     */
    public void setAudience(String audience) {
        this.body.audience = audience;
    }

    /**
     * @return the expires
     */
    public long getExpires() {
        return body.expires;
    }

    /**
     * @param expires the expires to set
     */
    public void setExpires(long expires) {
        this.body.expires = expires;
    }

    /**
     * @return the notBefore
     */
    public long getNotBefore() {
        return body.notBefore;
    }

    /**
     * @param notBefore the notBefore to set
     */
    public void setNotBefore(long notBefore) {
        this.body.notBefore = notBefore;
    }

    /**
     * @return the issuer
     */
    public String getIssuer() {
        return body.issuer;
    }

    /**
     * @param issuer the issuer to set
     */
    public void setIssuer(String issuer) {
        this.body.issuer = issuer;
    }

    /**
     * @return the issuedAt
     */
    public long getIssuedAt() {
        return body.issuedAt;
    }

    /**
     * @param issuedAt the Issued At to set
     */
    public void setIssuedAt(long issuedAt) {
        this.body.issuedAt = issuedAt;
    }

    /**
     * @return the subject
     */
    public String getSubject() {
        return body.subject;
    }

    /**
     * @param subject the subject to set
     */
    public void setSubject(String subject) {
        this.body.subject = subject;
    }

    /**
     * @return the id
     */
    public String getId() {
        return body.id;
    }

    /**
     * @param id the id to set
     */
    public void setId(String id) {
        this.body.id = id;
    }
}

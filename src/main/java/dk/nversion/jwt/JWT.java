package dk.nversion.jwt;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
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
        private long expires;
        @JsonProperty("nbf")
        private long notBefore;
        @JsonProperty("sub")
        private String subject;
    }

    private Header header;
    private Body body;
    
    private byte[] key;
    private X509Certificate certificate;
    
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
        this.key = key;
    }
    
    public JWT(Algorithm algorithm, X509Certificate certificate) throws JWTException {
        
        if(algorithm.name().startsWith("HS")) {
            throw new JWTException("This algorithm needs a shared key");
        }
        
        this.body = new Body();
        this.header = new Header();
        this.header.algorithm = algorithm;
    }
    
    public JWT(String token, String key) throws JWTException, IOException, InvalidKeyException, NoSuchAlgorithmException {
        this(token, key.getBytes(StandardCharsets.UTF_8));
    }
    
    public JWT(String token, byte [] key) throws JWTException, IOException, InvalidKeyException, NoSuchAlgorithmException {
        if(StringUtils.countMatches(token, ".") != 2) {
            throw new JWTException("Not a valid JWT token as it does not contain two dots");
        }
        
        int header_offset = token.indexOf('.');
        int body_offset = token.indexOf('.', header_offset + 1);
        
        ObjectMapper mapper = new ObjectMapper();

        this.header = mapper.readValue(Base64.decodeBase64(token.substring(0, header_offset)), Header.class);
        this.body = mapper.readValue(Base64.decodeBase64(token.substring(header_offset + 1, body_offset)), Body.class);
        byte[] signature_bytes = Base64.decodeBase64(token.substring(body_offset + 1, token.length()));
        
        byte[] calculated_signature_bytes;
        switch (header.algorithm) {
            case HS256:
            case HS384:
            case HS512:
                Mac mac = Mac.getInstance(header.algorithm.getValue());
                mac.init(new SecretKeySpec(key, header.algorithm.getValue()));
                calculated_signature_bytes = mac.doFinal(Arrays.copyOfRange(token.getBytes(StandardCharsets.UTF_8), 0, body_offset));
                break;
            case RS256:
            case RS384:
            case RS512:
                throw new JWTException("Not supported");
            default:
                throw new JWTException("Unsupported signing method");
        }
        
        if(!MessageDigest.isEqual(signature_bytes, calculated_signature_bytes)) {
            throw new JWTException("Signature validation failed");
        }
        
    }
    
    public String encode() throws JWTException, JsonProcessingException, NoSuchAlgorithmException, InvalidKeyException {
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
                case HS512:
                    Mac mac = Mac.getInstance(header.algorithm.getValue());
                    mac.init(new SecretKeySpec(key, header.algorithm.getValue()));
                    signature_bytes = Base64.encodeBase64URLSafe(mac.doFinal(header_body_bytes));
                    break;
                case RS256:
                case RS384:
                case RS512:
                    throw new JWTException("Not supported");
                default:
                    throw new JWTException("Unsupported signing method");
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

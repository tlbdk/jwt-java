package dk.nversion;

import static java.nio.charset.StandardCharsets.US_ASCII;
import javax.xml.bind.DatatypeConverter;

public class Base64URL {
     public static String encode(byte[] data) {
        String base64data = DatatypeConverter.printBase64Binary(data);
        byte[] bytes = base64data.getBytes(US_ASCII);

         // Base64url encoding doesn't use padding chars
        int paddingCount = 0;
        for (int i = bytes.length - 1; i > 0; i--) {
            if (bytes[i] == '=') {
                paddingCount++;
            } else {
                break;
            }
        }
        
        // Replace URL-unfriendly charatesrs with url friendly versions
        for (int i = 0; i < bytes.length - paddingCount; i++) {
            if (bytes[i] == '+') {
                bytes[i] = '-';
            } else if (bytes[i] == '/') {
                bytes[i] = '_';
            }
        }
        
        // Return base64url ended string without padding
        return new String(bytes, 0, bytes.length - paddingCount, US_ASCII);
    }

    public static byte[] decode(String encoded) {
        return DatatypeConverter.parseBase64Binary(encoded);
    }
}

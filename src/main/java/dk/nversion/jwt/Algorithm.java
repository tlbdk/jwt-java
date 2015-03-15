package dk.nversion.jwt;

public enum Algorithm {
	HS256("HmacSHA256"),
    HS384("HmacSHA384"),
    HS512("HmacSHA512"),
    RS256("SHA256withRSA"),
    RS384("SHA384withRSA"),
    RS512("SHA512withRSA");

    private final String value;
    
	private Algorithm(String value) {
		this.value = value;
	}
    
	public String getValue() {
		return value;
	}
}

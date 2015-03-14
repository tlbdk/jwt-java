package dk.nversion.jwt;

public enum Algorithm {
	HS256("HmacSHA256"),
    HS384("HmacSHA384"),
    HS512("HmacSHA512"),
    RS256("RS256"),
    RS384("RS384"),
    RS512("RS512");

    private final String value;
    
	private Algorithm(String value) {
		this.value = value;
	}
    
	public String getValue() {
		return value;
	}
}


public interface Functions {
	
	/**
	 * Transfromation in the Cipher and Inverse Cipher in which a Round
	 * Key is added to the State using an XOR operation. The length of a
	 * Round Key equals the size of the State (i.e., for Nb = 4), the Round
	 * Key length equals 128 bits/16 bytes).
	 */
	public void AddRoundKey();
	
	/**
	 * Transformation in the Inverse Cipher that is the inverse of
	 * MixColumns().
	 */
	public void InvMixColumns();

	/**
	 * Transformation in the 
	 */
	
}

package aes;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;

/**
 * Interface for the AESCrypt-Class
 * @author Philipp Kolnhofer
 * @version 1.0
 */
public interface AESCryptInterface {
	/**
	 * Constant for signalling Cipher Block Chaining Mode (CBC-Mode)
	 */
	public static int CBC_MODE = 0x1;
	/**
	 * Constant for signalling Electronic Code Book Mode (ECB-Mode)
	 */
	public static int ECB_MODE = 0x0;

	/**
	 * Decrypts the text.
	 */
	public void decrypt();

	/**
	 * Encrypts the text.
	 */
	public void encrypt();

	/**
	 * Gets the collected statistics of byte-frequencies collected by this
	 * instance.
	 * @return A <code>HashMap&lt;Byte, Integer&gt;</code> containing the
	 * accumulated frequencies of all bytes produced by encrypting the input
	 * texts.
	 */
	public HashMap<Byte, Integer> getCiphFreq();

	/**
	 * Gets the collected statistics of byte-frequencies collected by this
	 * instance.
	 * @return A <code>HashMap&lt;Byte, Integer&gt;</code> containing the
	 * accumulated frequencies of all bytes encountered while processing the
	 * input texts.
	 */
	public HashMap<Byte, Integer> getOrigFreq();

	/**
	 * Gets the bytes stored for/after encryption/decryption.
	 * @return the stored bytes
	 */
	public byte[] getText();

	/**
	 * Resets the statistics of byte-frequencies collected by this instance by
	 * removing all entries from the HashMaps.
	 */
	public void resetStats();

	/**
	 * Sets the initial vector (IV) used for CBC.
	 * @param in The initial vector to be used.
	 */
	public void setIV(byte[] in);

	/**
	 * Sets the text to be encrypted or decrypted.
	 * @param in The text to be encrypted or decrypted.
	 */
	public void setText(byte[] in);

	/**
	 * Decrypts the bytes of the input stream and writes them to the output
	 * stream.
	 * @param in the input stream to be decrypted
	 * @param out the output stream the decrypted data should be written to
	 */
	public void streamDecrypt(InputStream in, OutputStream out);

	/**
	 * Encrypts the bytes of the input stream and writes them to the output
	 * stream.<br />
	 * If the number of Bytes on the input stream is no integral multiple of 16
	 * the last block is filled to 16 with <code>0</code>-Bytes
	 * @param in the input stream to read the data to be encrypted from
	 * @param out the output stream the encrypted data should be put
	 */
	public void streamEncrypt(InputStream in, OutputStream out);
	
}

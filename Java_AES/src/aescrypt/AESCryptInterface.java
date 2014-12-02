package aescrypt;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.TreeMap;

/**
 * Interface for the AESCrypt-Class
 * @author Philipp Kolnhofer
 * @version 1.2
 */
public interface AESCryptInterface {
    
    /**
     * Constant for signalling Cipher Block Chaining Mode (CBC-Mode)
     */
    public static final int CBC_MODE = 0x1;
    /**
     * Constant for signalling Electronic Code Book Mode (ECB-Mode)
     */
    public static final int ECB_MODE = 0x0;

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
     * @return A <code>TreeMap&lt;Byte, Integer&gt;</code> containing the
     * accumulated frequencies of all bytes produced by encrypting the input
     * texts.
     */
    public TreeMap<Integer, Integer> getCiphFreq();

    /**
     * Gets the amount of bytes processed by this instance since creation or the
     * last reset.
     * @return the amount of processed bytes
     */
    public int getCount();

    /**
     * Gets the collected statistics of byte-frequencies collected by this
     * instance.
     * @return A <code>TreeMap&lt;Byte, Integer&gt;</code> containing the
     * accumulated frequencies of all bytes encountered while processing the
     * input texts.
     */
    public TreeMap<Integer, Integer> getOrigFreq();

    /**
     * Gets the bytes stored for/after encryption/decryption.
     * @return the stored bytes
     */
    public byte[] getText();

    /**
     * Resets the statistics of byte-frequencies collected by this instance by
     * removing all entries from the TreeMaps.
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

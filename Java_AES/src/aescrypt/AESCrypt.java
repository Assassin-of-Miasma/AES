package aescrypt;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.TreeMap;

/**
 * Class for AES Encryption and Decryption
 * @author Philipp Kolnhofer
 * @version 1.8
 */
public class AESCrypt implements AESCryptInterface {
    
    private static final byte[][] sBox = 
    {
        {(byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76},
        {(byte)0xca, (byte)0x82, (byte)0xc9, (byte)0x7d, (byte)0xfa, (byte)0x59, (byte)0x47, (byte)0xf0, (byte)0xad, (byte)0xd4, (byte)0xa2, (byte)0xaf, (byte)0x9c, (byte)0xa4, (byte)0x72, (byte)0xc0},
        {(byte)0xb7, (byte)0xfd, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3f, (byte)0xf7, (byte)0xcc, (byte)0x34, (byte)0xa5, (byte)0xe5, (byte)0xf1, (byte)0x71, (byte)0xd8, (byte)0x31, (byte)0x15},
        {(byte)0x04, (byte)0xc7, (byte)0x23, (byte)0xc3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9a, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xe2, (byte)0xeb, (byte)0x27, (byte)0xb2, (byte)0x75},
        {(byte)0x09, (byte)0x83, (byte)0x2c, (byte)0x1a, (byte)0x1b, (byte)0x6e, (byte)0x5a, (byte)0xa0, (byte)0x52, (byte)0x3b, (byte)0xd6, (byte)0xb3, (byte)0x29, (byte)0xe3, (byte)0x2f, (byte)0x84},
        {(byte)0x53, (byte)0xd1, (byte)0x00, (byte)0xed, (byte)0x20, (byte)0xfc, (byte)0xb1, (byte)0x5b, (byte)0x6a, (byte)0xcb, (byte)0xbe, (byte)0x39, (byte)0x4a, (byte)0x4c, (byte)0x58, (byte)0xcf},
        {(byte)0xd0, (byte)0xef, (byte)0xaa, (byte)0xfb, (byte)0x43, (byte)0x4d, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xf9, (byte)0x02, (byte)0x7f, (byte)0x50, (byte)0x3c, (byte)0x9f, (byte)0xa8},
        {(byte)0x51, (byte)0xa3, (byte)0x40, (byte)0x8f, (byte)0x92, (byte)0x9d, (byte)0x38, (byte)0xf5, (byte)0xbc, (byte)0xb6, (byte)0xda, (byte)0x21, (byte)0x10, (byte)0xff, (byte)0xf3, (byte)0xd2},
        {(byte)0xcd, (byte)0x0c, (byte)0x13, (byte)0xec, (byte)0x5f, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xc4, (byte)0xa7, (byte)0x7e, (byte)0x3d, (byte)0x64, (byte)0x5d, (byte)0x19, (byte)0x73},
        {(byte)0x60, (byte)0x81, (byte)0x4f, (byte)0xdc, (byte)0x22, (byte)0x2a, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xee, (byte)0xb8, (byte)0x14, (byte)0xde, (byte)0x5e, (byte)0x0b, (byte)0xdb},
        {(byte)0xe0, (byte)0x32, (byte)0x3a, (byte)0x0a, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5c, (byte)0xc2, (byte)0xd3, (byte)0xac, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xe4, (byte)0x79},
        {(byte)0xe7, (byte)0xc8, (byte)0x37, (byte)0x6d, (byte)0x8d, (byte)0xd5, (byte)0x4e, (byte)0xa9, (byte)0x6c, (byte)0x56, (byte)0xf4, (byte)0xea, (byte)0x65, (byte)0x7a, (byte)0xae, (byte)0x08},
        {(byte)0xba, (byte)0x78, (byte)0x25, (byte)0x2e, (byte)0x1c, (byte)0xa6, (byte)0xb4, (byte)0xc6, (byte)0xe8, (byte)0xdd, (byte)0x74, (byte)0x1f, (byte)0x4b, (byte)0xbd, (byte)0x8b, (byte)0x8a},
        {(byte)0x70, (byte)0x3e, (byte)0xb5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xf6, (byte)0x0e, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xb9, (byte)0x86, (byte)0xc1, (byte)0x1d, (byte)0x9e},
        {(byte)0xe1, (byte)0xf8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xd9, (byte)0x8e, (byte)0x94, (byte)0x9b, (byte)0x1e, (byte)0x87, (byte)0xe9, (byte)0xce, (byte)0x55, (byte)0x28, (byte)0xdf},
        {(byte)0x8c, (byte)0xa1, (byte)0x89, (byte)0x0d, (byte)0xbf, (byte)0xe6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2d, (byte)0x0f, (byte)0xb0, (byte)0x54, (byte)0xbb, (byte)0x16}
    };
    private static final byte[][] invSBox = 
    {
        {(byte)0x52, (byte)0x09, (byte)0x6a, (byte)0xd5, (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38, (byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb},
        {(byte)0x7c, (byte)0xe3, (byte)0x39, (byte)0x82, (byte)0x9b, (byte)0x2f, (byte)0xff, (byte)0x87, (byte)0x34, (byte)0x8e, (byte)0x43, (byte)0x44, (byte)0xc4, (byte)0xde, (byte)0xe9, (byte)0xcb},
        {(byte)0x54, (byte)0x7b, (byte)0x94, (byte)0x32, (byte)0xa6, (byte)0xc2, (byte)0x23, (byte)0x3d, (byte)0xee, (byte)0x4c, (byte)0x95, (byte)0x0b, (byte)0x42, (byte)0xfa, (byte)0xc3, (byte)0x4e},
        {(byte)0x08, (byte)0x2e, (byte)0xa1, (byte)0x66, (byte)0x28, (byte)0xd9, (byte)0x24, (byte)0xb2, (byte)0x76, (byte)0x5b, (byte)0xa2, (byte)0x49, (byte)0x6d, (byte)0x8b, (byte)0xd1, (byte)0x25},
        {(byte)0x72, (byte)0xf8, (byte)0xf6, (byte)0x64, (byte)0x86, (byte)0x68, (byte)0x98, (byte)0x16, (byte)0xd4, (byte)0xa4, (byte)0x5c, (byte)0xcc, (byte)0x5d, (byte)0x65, (byte)0xb6, (byte)0x92},
        {(byte)0x6c, (byte)0x70, (byte)0x48, (byte)0x50, (byte)0xfd, (byte)0xed, (byte)0xb9, (byte)0xda, (byte)0x5e, (byte)0x15, (byte)0x46, (byte)0x57, (byte)0xa7, (byte)0x8d, (byte)0x9d, (byte)0x84},
        {(byte)0x90, (byte)0xd8, (byte)0xab, (byte)0x00, (byte)0x8c, (byte)0xbc, (byte)0xd3, (byte)0x0a, (byte)0xf7, (byte)0xe4, (byte)0x58, (byte)0x05, (byte)0xb8, (byte)0xb3, (byte)0x45, (byte)0x06},
        {(byte)0xd0, (byte)0x2c, (byte)0x1e, (byte)0x8f, (byte)0xca, (byte)0x3f, (byte)0x0f, (byte)0x02, (byte)0xc1, (byte)0xaf, (byte)0xbd, (byte)0x03, (byte)0x01, (byte)0x13, (byte)0x8a, (byte)0x6b},
        {(byte)0x3a, (byte)0x91, (byte)0x11, (byte)0x41, (byte)0x4f, (byte)0x67, (byte)0xdc, (byte)0xea, (byte)0x97, (byte)0xf2, (byte)0xcf, (byte)0xce, (byte)0xf0, (byte)0xb4, (byte)0xe6, (byte)0x73},
        {(byte)0x96, (byte)0xac, (byte)0x74, (byte)0x22, (byte)0xe7, (byte)0xad, (byte)0x35, (byte)0x85, (byte)0xe2, (byte)0xf9, (byte)0x37, (byte)0xe8, (byte)0x1c, (byte)0x75, (byte)0xdf, (byte)0x6e},
        {(byte)0x47, (byte)0xf1, (byte)0x1a, (byte)0x71, (byte)0x1d, (byte)0x29, (byte)0xc5, (byte)0x89, (byte)0x6f, (byte)0xb7, (byte)0x62, (byte)0x0e, (byte)0xaa, (byte)0x18, (byte)0xbe, (byte)0x1b},
        {(byte)0xfc, (byte)0x56, (byte)0x3e, (byte)0x4b, (byte)0xc6, (byte)0xd2, (byte)0x79, (byte)0x20, (byte)0x9a, (byte)0xdb, (byte)0xc0, (byte)0xfe, (byte)0x78, (byte)0xcd, (byte)0x5a, (byte)0xf4},
        {(byte)0x1f, (byte)0xdd, (byte)0xa8, (byte)0x33, (byte)0x88, (byte)0x07, (byte)0xc7, (byte)0x31, (byte)0xb1, (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, (byte)0x80, (byte)0xec, (byte)0x5f},
        {(byte)0x60, (byte)0x51, (byte)0x7f, (byte)0xa9, (byte)0x19, (byte)0xb5, (byte)0x4a, (byte)0x0d, (byte)0x2d, (byte)0xe5, (byte)0x7a, (byte)0x9f, (byte)0x93, (byte)0xc9, (byte)0x9c, (byte)0xef},
        {(byte)0xa0, (byte)0xe0, (byte)0x3b, (byte)0x4d, (byte)0xae, (byte)0x2a, (byte)0xf5, (byte)0xb0, (byte)0xc8, (byte)0xeb, (byte)0xbb, (byte)0x3c, (byte)0x83, (byte)0x53, (byte)0x99, (byte)0x61},
        {(byte)0x17, (byte)0x2b, (byte)0x04, (byte)0x7e, (byte)0xba, (byte)0x77, (byte)0xd6, (byte)0x26, (byte)0xe1, (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0c, (byte)0x7d}  
    };
    private static final int irrPol = 0b00011011;
    
    private final byte[][] textTable = new byte[4][4];
    private final byte[][] keyTable;
    private byte[][] expandedKey;
    private final byte[][] iv = new byte[4][4];
    private final int nk;
    private final int nr;
    private final int mode;
    private int count;
    private final TreeMap<Integer, Integer> origFreq = new TreeMap<>();
    private final TreeMap<Integer, Integer> ciphFreq = new TreeMap<>();
    
    public final class InvalidArgumentException extends Exception{

        private InvalidArgumentException(String msg) {
            super(msg);
        }
    }
    
    private void fillTable(byte[] in, byte[][] table){
        for (int row = 0; row < 4; row++){
            for (int col = 0; col < Math.ceil((double)in.length / 4); col++){
                table[row][col] = in[col*4 + row];
            }
        }
    }
    
//    private void printTable(byte[][] table){
//        for (int row = 0; row < 4; row++){
//            for (int col = 0; col < table[row].length; col++){
//                System.out.print(String.format("%02x ", table[row][col]));
//            }
//            System.out.println("");
//        }
//    }
    
    private void replicateTable(byte[][] src, byte[][] dest){
        for (int row = 0; row < src.length; row++){
            for (int col = 0; col < src[row].length; col++){
                dest[row][col] = src[row][col];
            }
        }
    }
    
    private void combineTextIV(){
        for (int row = 0; row < 4; row++){
            for (int col = 0; col < 4; col++){
                this.textTable[row][col] = (byte)(this.textTable[row][col] ^ this.iv[row][col]);
            }
        }
    }
    
    /**
     * Constructor for AESCrypt.<br />
     * The parameter is the key to be used for encryption and decryption,
     * represented by an array of <code>byte</code>-values. The used mode for
     * encryption ist the ECB-Mode. The call of this function is equivalent to
     * <blockquote><code>AESCrypt(key, null, AESCrypt.ECB_MODE);</code></blockquote>
     * @param key - The key to be used for encryption and decryption as array of
     * <code>byte</code>-values, allowed lengths: 16, 24 or 32
     * @throws InvalidArgumentException - if the length of the key is invalid. 
     * According to the specification the key length has to be 128 bit, 192 bit 
     * or 256 bit, so the array used as parameter has to have 16, 24 or 32 
     * entries
     */
    public AESCrypt(byte[] key) throws InvalidArgumentException{
        this(key, null, AESCrypt.ECB_MODE);
    }
    
    /**
     * Constructor for AESCrypt.<br />
     * The parameter is the key to be used for encryption and decryption,
     * represented as String. The used mode for
     * encryption ist the ECB-Mode. The call of this function is equivalent to
     * <blockquote><code>AESCrypt(key.getBytes(), null, AESCrypt.ECB_MODE);</code></blockquote>
     * @param key - The key to be used for encryption and decryption as String, 
     * allowed lengths: 16, 24 or 32 Byte
     * @throws InvalidArgumentException - if the length of the key is invalid. 
     * According to the specification the key length has to be 128 bit, 192 bit 
     * or 256 bit, so the String used as parameter has to have 16, 24 or 32 
     * Byte
     */
    public AESCrypt(String key) throws InvalidArgumentException{
        this(key.getBytes(), null, AESCrypt.ECB_MODE);
    }
    
    
    
    /**
     * Constructor for AESCrypt.<br />
     * The first parameter is the key to be used for encryption and decryption,
     * represented as String. The used mode for
     * encryption ist the CCB-Mode. The call of this function is equivalent to
     * <blockquote><code>AESCrypt(key.getBytes(), iv, AESCrypt.ECB_MODE);</code></blockquote>
     * @param key - The key to be used for encryption and decryption as String, 
     * allowed lengths: 16, 24 or 32 Byte
     * @param iv - The initial vector to be used for CBC Mode
     * @throws InvalidArgumentException - if the length of the key is invalid. 
     * According to the specification the key length has to be 128 bit, 192 bit 
     * or 256 bit, so the String used as parameter has to have 16, 24 or 32 
     * Byte
     */
    public AESCrypt(String key, byte[] iv) throws InvalidArgumentException{
        this(key.getBytes(), iv, AESCrypt.CBC_MODE);
    }
    
    
    
    /**
     * Constructor for AESCrypt.<br />
     * The parameter is the key to be used for encryption and decryption,
     * represented as array of bytes. The used mode for
     * encryption ist the CCB-Mode. The call of this function is equivalent to
     * <blockquote><code>AESCrypt(key.getBytes(), iv, AESCrypt.ECB_MODE);</code></blockquote>
     * @param key - The key to be used for encryption and decryption as array of bytes, 
     * allowed lengths: 16, 24 or 32 Byte
     * @param iv - The initial vector to be used for CBC Mode
     * @throws InvalidArgumentException - if the length of the key is invalid. 
     * According to the specification the key length has to be 128 bit, 192 bit 
     * or 256 bit, so the String used as parameter has to have 16, 24 or 32 
     * Byte
     */
    public AESCrypt(byte[] key, byte[] iv) throws InvalidArgumentException{
        this(key, iv, AESCrypt.CBC_MODE);
    }
    
    /**
     * Constructor for AESCrypt.<br />
     * The parameter is the key to be used for encryption and decryption,
     * represented as String. The used mode for encryption ist the mode given by
     * <code>mode</code>. 
     * The call of this function is equivalent to 
     * <blockquote><code>AESCrypt(key.getBytes(), iv, mode);</code></blockquote>
     * @param key the key for encryption and decryption, represented as String
     * @param iv the initial vector used in the CBC-Mode. Is ignored, if
     * <blockquote><code>mode=AESCrypt.ECB_MODE</code></blockquote>In this 
     * case, it might be <code>null</code>.<br />If this parameter is 
     * <code>null</code> and 
     * <blockquote><code>mode != AESCrypt.ECB_MODE</code></blockquote>
     * an <code>InvalidArgumentException</code> will be thrown
     * @param mode the mode of operation. <code>AESCrypt.ECB_MODE</code> will 
     * trigger the ECB-Mode (standard), while <code>AESCrypt.CBC_MODE</code>
     * triggers the CBC-Mode.
     * @throws InvalidArgumentException if a parameter fails to meet the 
     * limitations given by the specification
     */
    public AESCrypt(String key, byte[] iv, int mode) throws InvalidArgumentException{
        this(key.getBytes(), iv, mode);
    }
    
    /**
     * Constructor for AESCrypt.<br />
     * The parameter is the key to be used for encryption and decryption,
     * represented as String. The used mode for encryption ist the mode given by
     * <code>mode</code>.
     * @param key the key for encryption and decryption, represented as array of
     * <code>byte</code>-values
     * @param iv the initial vector used in the CBC-Mode. Is ignored, if
     * <blockquote><code>mode=AESCrypt.ECB_MODE</code></blockquote>In this 
     * case, it might be <code>null</code>.<br />If this parameter is 
     * <code>null</code> and 
     * <blockquote><code>mode != AESCrypt.ECB_MODE</code></blockquote>
     * an <code>InvalidArgumentException</code> will be thrown
     * @param mode the mode of operation. <code>AESCrypt.ECB_MODE</code> will 
     * trigger the ECB-Mode (standard), while <code>AESCrypt.CBC_MODE</code>
     * triggers the CBC-Mode.
     * @throws InvalidArgumentException if a parameter fails to meet the 
     * limitations given by the specification
     */
    public AESCrypt(byte[] key, byte[] iv, int mode) throws InvalidArgumentException{
        if (mode != AESCrypt.ECB_MODE && mode != AESCrypt.CBC_MODE){
            throw new InvalidArgumentException("Invalid mode");
        }
        if (key.length != 16 && key.length != 24 && key.length != 32){
            throw new InvalidArgumentException("Invalid key length");
        }
        if (iv == null && mode != AESCrypt.ECB_MODE){
            throw new InvalidArgumentException("Initial vector needed for CBC mode");
        }
        if (iv != null && iv.length != 16) {
            throw new InvalidArgumentException("Invalid initial vector length");
        }
        this.keyTable = new byte[4][(int)Math.ceil((double)key.length / 4)];
        this.mode = mode;
        if (mode != AESCrypt.ECB_MODE){
            fillTable(iv, this.iv);
        }
        fillTable(Arrays.copyOf(key, (int)Math.ceil((double)key.length / 4) * 4), this.keyTable);
        this.nk = this.keyTable[0].length;
        this.nr = nk + 6;
        expandKey();
    }
    
    /**
     * Sets the text to be encrypted or decrypted.
     * @param in The text to be encrypted or decrypted.
     */
    @Override
    public void setText(byte[] in){
        fillTable(Arrays.copyOf(in, (int)Math.ceil((double)in.length / 4) * 4), this.textTable);
    }
    
    /**
     * Sets the initial vector (IV) used for CBC.
     * @param in The initial vector to be used.
     */
    @Override
    public void setIV(byte[] in){
        fillTable(Arrays.copyOf(in, (int)Math.ceil((double)in.length / 4) * 4), this.iv);
    }
    
    /**
     * Gets the bytes stored for/after encryption/decryption.
     * @return the stored bytes
     */
    @Override
    public byte[] getText(){
        byte[] buf = new byte[16];
        for (int row = 0; row < 4; row++){
            for (int col = 0; col < 4; col++){
                buf[col * 4 + row] = this.textTable[row][col];
            }
        }
        return buf;
    }
    
    private void subBytes(){
        for (int row = 0; row < 4; row++){
            for (int col = 0; col < this.textTable[0].length; col++){
                int state = textTable[row][col];
                textTable[row][col] = AESCrypt.sBox[(state & 0xFF)>>4][(state & 0xFF)%16];
            }
        }
    }
    
    private void invSubBytes(){
        for (int row = 0; row < 4; row++){
            for (int col = 0; col < this.textTable[0].length; col++){
                int state = textTable[row][col];
                textTable[row][col] = AESCrypt.invSBox[(state & 0xFF)>>4][(state & 0xFF)%16];
            }
        }
    }
    
    private byte[] concat(byte[] front, byte[] end){
        byte[] buf = new byte[front.length+end.length];
        System.arraycopy(front, 0, buf, 0, front.length);
        System.arraycopy(end, 0, buf, front.length, end.length);
        return buf;
    }
    
    private void shiftRows(){
        for (int row = 1; row < 4; row++){
            this.textTable[row] = concat(Arrays.copyOfRange(this.textTable[row], row, this.textTable[row].length), Arrays.copyOf(this.textTable[row], row));
        }
    }
    
    private void invShiftRows(){
        for (int row = 1; row < 4; row++){
            this.textTable[row] = concat(Arrays.copyOfRange(this.textTable[row], this.textTable[row].length - row, this.textTable[row].length), Arrays.copyOfRange(this.textTable[row], 0, this.textTable[row].length - row));
        }
    }
    
    private byte gfMul(byte tableVal, int mult){
        switch (mult){
            case 0x01 : 
                return tableVal;
            case 0x02 :
                if ((tableVal & 0xFF) < 0b10000000) {
                    return (byte)(tableVal<<1);
                } else {
                    return (byte)((tableVal<<1) ^ AESCrypt.irrPol);
                }
            case 0x03 :
                return (byte)(gfMul(tableVal, 2) ^ tableVal);
            case 0x09 :
                return (byte)(gfMul(gfMul(gfMul(tableVal, 2), 2), 2) ^ tableVal);
            case 0x0b :
                return (byte)(gfMul((byte)(gfMul(gfMul(tableVal, 2), 2) ^ tableVal), 2) ^ tableVal);
            case 0x0d :
                return (byte)(gfMul(gfMul((byte)(gfMul(tableVal, 2) ^ tableVal), 2), 2) ^ tableVal);
            default   :
                return (byte)(gfMul((byte)(gfMul((byte)(gfMul(tableVal, 2) ^ tableVal), 2) ^ tableVal) , 2));
        }
    }
    
    private void mixColumns(){
        for (int col = 0; col < this.textTable[0].length; col++){
            byte b1 = this.textTable[0][col];
            byte b2 = this.textTable[1][col];
            byte b3 = this.textTable[2][col];
            byte b4 = this.textTable[3][col];
            this.textTable[0][col] = (byte)(gfMul(b1, 2) ^ gfMul(b2, 3) ^ b3 ^ b4);
            this.textTable[1][col] = (byte)(gfMul(b2, 2) ^ gfMul(b3, 3) ^ b4 ^ b1);
            this.textTable[2][col] = (byte)(gfMul(b3, 2) ^ gfMul(b4, 3) ^ b1 ^ b2);
            this.textTable[3][col] = (byte)(gfMul(b4, 2) ^ gfMul(b1, 3) ^ b2 ^ b3);
        }
    }
    
    
    private void invMixColumns(){
        for (int col = 0; col < this.textTable[0].length; col++){
            byte b1 = this.textTable[0][col];
            byte b2 = this.textTable[1][col];
            byte b3 = this.textTable[2][col];
            byte b4 = this.textTable[3][col];
            this.textTable[0][col] = (byte)(gfMul(b1, 0x0e) ^ gfMul(b2, 0x0b) ^ gfMul(b3, 0x0d) ^ gfMul(b4, 0x09));
            this.textTable[1][col] = (byte)(gfMul(b1, 0x09) ^ gfMul(b2, 0x0e) ^ gfMul(b3, 0x0b) ^ gfMul(b4, 0x0d));
            this.textTable[2][col] = (byte)(gfMul(b1, 0x0d) ^ gfMul(b2, 0x09) ^ gfMul(b3, 0x0e) ^ gfMul(b4, 0x0b));
            this.textTable[3][col] = (byte)(gfMul(b1, 0x0b) ^ gfMul(b2, 0x0d) ^ gfMul(b3, 0x09) ^ gfMul(b4, 0x0e));
        }
    }
    
    private byte[] subWord(byte[] in){
        byte[] res = new byte[in.length];
        for (int i = 0; i < in.length; i++){
            res[i] = AESCrypt.sBox[(in[i] & 0xFF)>>4][(in[i] & 0xFF)%16];
        }
        return res;
    }
    
    private byte[] rotWord(byte[] in){
        return concat(Arrays.copyOfRange(in, 1, in.length), new byte[]{in[0]});
    }
    
    private void expandKey(){
        int rconV = 1;
        this.expandedKey = new byte[4][nk*(nr + 1)];
        int col;
        for (col = 0; col < nk; col++){
            for (int row = 0; row < 4; row++){
                this.expandedKey[row][col] = this.keyTable[row][col];
            }
        }
        for (; col < nk*(nr + 1); col++){
            byte[] buf = new byte[]{this.expandedKey[0][col-1], 
                                    this.expandedKey[1][col-1], 
                                    this.expandedKey[2][col-1], 
                                    this.expandedKey[3][col-1]};
            if (col % nk == 0) {
                buf = subWord(rotWord(buf));
                buf[0] = (byte)((buf[0] & 0xFF) ^ rconV);
                rconV = (rconV << 1);
                if (rconV > 0b10000000) {
                    rconV = rconV ^ 0x11b;
                }
            } else if (nk > 6 && col % nk == 4){
                buf = subWord(buf);
            }
            for (int row = 0; row < 4; row++){
                this.expandedKey[row][col] = (byte)(this.expandedKey[row][col - 4] ^ buf[row]);
            }
        }
    }
    
    private void addRoundKey(int round){
        for (int col = 0; col < 4; col++){
            for (int row = 0; row < 4; row++){
                this.textTable[row][col] = (byte)(this.textTable[row][col] ^ this.expandedKey[row][round * 4 + col]);
            }
        }
    }
    
    /**
     * Encrypts the bytes of the input stream and writes them to the output 
     * stream.<br />
     * If the number of Bytes on the input stream is no integral multiple of 16
     * the last block is filled to 16 with <code>0</code>-Bytes
     * @param in the input stream to read the data to be encrypted from
     * @param out the output stream the encrypted data should be put
     */
    @Override
    public void streamEncrypt(InputStream in, OutputStream out){
        byte[] buffer = new byte[16];
        try {
            int read = in.read(buffer);
            while (read != -1) {
                if (read < 16) {
                    Arrays.fill(buffer, read, 16, (byte)0);
                }
                this.setText(buffer);
                encrypt();
                for (int row = 0; row < 4; row++){
                    for (int col = 0; col < 4; col++){
                        buffer[row + col * 4] = this.textTable[row][col];
                    }
                }
                out.write(buffer);
                read = in.read(buffer);
            }
            out.flush();
        } catch (Exception e){
            e.printStackTrace();
        }
        
    }
    
    /**
     * Decrypts the bytes of the input stream and writes them to the output 
     * stream.
     * @param in the input stream to be decrypted
     * @param out the output stream the decrypted data should be written to
     */
    @Override
    public void streamDecrypt(InputStream in, OutputStream out){
        byte[] buffer = new byte[16];
        try {
            int read = in.read(buffer);
            while (read != -1) {
                if (read < 16) {
                    Arrays.fill(buffer, read, 16, (byte)0);
                }
                this.setText(buffer);
                decrypt();
                for (int row = 0; row < 4; row++){
                    for (int col = 0; col < 4; col++){
                        buffer[row + col * 4] = this.textTable[row][col];
                    }
                }
                out.write(buffer);
                read = in.read(buffer);
            }
            out.flush();
        } catch (Exception e){
            e.printStackTrace();
        }
        
    }
    
    private void getStat(byte[][] buf, TreeMap<Integer, Integer> hash){
        this.count += buf.length* buf[0].length;
        for (int row = 0; row < buf.length; row++){
            for (int col = 0; col < buf[0].length; col++){
                if (hash.containsKey(0xFF & buf[row][col])){
                    hash.put(0xFF & buf[row][col], hash.get(0xFF & buf[row][col])+1);
                } else {
                    hash.put(0xFF & buf[row][col], 1);
                }
            }
        }
    }
    
    /**
     * Resets the statistics of byte-frequencies collected by this instance by 
     * removing all entries from the TreeMaps.
     */
    @Override
    public void resetStats(){
        this.ciphFreq.clear();
        this.origFreq.clear();
        this.count = 0;
    }

    /**
     * Gets the collected statistics of byte-frequencies collected by this 
     * instance.
     * @return A <code>TreeMap&lt;Byte, Integer&gt;</code> containing the 
     * accumulated frequencies of all bytes encountered while processing the 
     * input texts.
     */
    @Override
    public TreeMap<Integer, Integer> getOrigFreq() {
        return origFreq;
    }

    /**
     * Gets the collected statistics of byte-frequencies collected by this 
     * instance.
     * @return A <code>TreeMap&lt;Byte, Integer&gt;</code> containing the 
     * accumulated frequencies of all bytes produced by encrypting the input 
     * texts.
     */
    @Override
    public TreeMap<Integer, Integer> getCiphFreq() {
        return ciphFreq;
    }

    /**
     * Gets the amount of bytes processed by this instance since creation or the
     * last reset.
     * @return the amount of processed bytes
     */
    @Override
    public int getCount() {
        return count;
    }
    
    /**
     * Encrypts the text.
     */
    @Override
    public void encrypt(){
        int round = 0;
            /*System.out.println("Text (Origin):");
            printTable(textTable);
            System.out.println("-----------");*/
        getStat(this.textTable, this.origFreq);
        if (this.mode == AESCrypt.CBC_MODE){
            combineTextIV();
        }
        addRoundKey(round++);
            /*System.out.println("after addRoundKey:");
            printTable(textTable);
            System.out.println("-----------");*/
        for (; round < nr; round++){
            subBytes();
                /*System.out.println("after subBytes:");
                printTable(textTable);
                System.out.println("-----------");*/
            shiftRows();
                /*System.out.println("after shiftRows:");
                printTable(textTable);
                System.out.println("-----------");*/
            mixColumns();
                /*System.out.println("after mixColumns:");
                printTable(textTable);
                System.out.println("-----------");*/
            addRoundKey(round);
                /*System.out.println("after addRoundKey(" + round + "):");
                printTable(textTable);
                System.out.println("-----------");*/
        }
        subBytes();
            /*System.out.println("after subBytes:");
            printTable(textTable);
            System.out.println("-----------");*/
        shiftRows();
            /*System.out.println("after shiftRows:");
            printTable(textTable);
            System.out.println("-----------");*/
        addRoundKey(round);
            /*System.out.println("after addRoundKey(" + round + "):");
            printTable(textTable);
            System.out.println("-----------");*/
        getStat(this.textTable, this.ciphFreq);
        if (this.mode == AESCrypt.CBC_MODE){
            replicateTable(this.textTable, this.iv);
        }
    }
    
    /**
     * Decrypts the text.
     */
    @Override
    public void decrypt(){
        int round = nr;
            /*System.out.println("Text (Origin):");
            printTable(textTable);
            System.out.println("-----------");*/
        getStat(this.textTable, this.origFreq);
        byte[][] temp = new byte[4][4];
        replicateTable(this.textTable, temp);
        addRoundKey(round--);
            /*System.out.println("after addRoundKey:");
            printTable(textTable);
            System.out.println("-----------");*/
        for (; round > 0; round--){
            invShiftRows();
                /*System.out.println("after shiftRows:");
                printTable(textTable);
                System.out.println("-----------");*/
            invSubBytes();
                /*System.out.println("after subBytes:");
                printTable(textTable);
                System.out.println("-----------");*/
            addRoundKey(round);
                /*System.out.println("after addRoundKey(" + round + "):");
                printTable(textTable);
                System.out.println("-----------");*/
            invMixColumns();
                /*System.out.println("after mixColumns:");
                printTable(textTable);
                System.out.println("-----------");*/
        }
        invShiftRows();
            /*System.out.println("after shiftRows:");
            printTable(textTable);
            System.out.println("-----------");*/
        invSubBytes();
            /*System.out.println("after subBytes:");
            printTable(textTable);
            System.out.println("-----------");*/
        addRoundKey(round);
            /*System.out.println("after addRoundKey(" + round + "):");
            printTable(textTable);
            System.out.println("-----------");*/
        getStat(this.textTable, this.ciphFreq);
        if (this.mode == AESCrypt.CBC_MODE){
            combineTextIV();
            replicateTable(temp, this.iv);
        }
    }
    
}

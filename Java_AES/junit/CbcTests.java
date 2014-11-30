import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import aes.AESCrypt;
import aes.AESCrypt.InvalidArgumentException;


public class CbcTests {
	
	private String key 	= "1234567891234567";
	private String iv 	= "1234567891234567";
	
	private AESCrypt aes;
	
	@Before
	public void createAesCrypt() throws InvalidArgumentException {
		aes = new AESCrypt(key.getBytes(), iv.getBytes(), AESCrypt.CBC_MODE);
	}
	
//	@Before
//	public void encrypt() throws InvalidArgumentException {
//		aes.encrypt();
//		Assert.assertEquals("bt\\»ûRSLÇ‡¡", new String(aes.getText()));
//	}
	
//	@Test
//	public void decrypt() {
//		aes.decrypt();
//		Assert.assertEquals("Hallo Welt", new String(aes.getText()));
//	}
	
	@Test
	public void isItEquals() {
		String text = "Hello World\0\0\0\0\0";
		aes.setText("Hallo Welt".getBytes());
		aes.encrypt();
		System.out.println(new String(aes.getText()));
		aes.setIV(iv.getBytes());
		aes.decrypt();
		System.out.println(new String(aes.getText()));
		Assert.assertArrayEquals(text.getBytes(), aes.getText());
		System.out.println(text.equals(new String(aes.getText())));
	}
	
//	@Test
	public void whatAreTheOdds() {
		for(int i=0; i<255; ++i) {
			System.out.println(i+" "+(char)i);
		}
	}

}

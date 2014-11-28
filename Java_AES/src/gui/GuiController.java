package gui;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.net.URL;
import java.util.Date;
import java.util.Observable;
import java.util.Random;
import java.util.ResourceBundle;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import aes.AESCrypt;
import aes.AESCrypt.InvalidArgumentException;
import application.StartAes;


public class GuiController extends Observable implements Initializable {
	
	@FXML private RadioButton rb_process_file;
	@FXML private Label lbl_saveFile;
	@FXML private Label lbl_openFile;
	
	@FXML private RadioButton rb_process_text;
	@FXML private TextArea txta_input;
	@FXML private TextArea txta_output;
	
	
	@FXML private RadioButton rb_iv_random;
	@FXML private RadioButton rb_iv_own;
	@FXML private TextField txt_initalVector;
	@FXML private Label lbl_usedIv;
	
	@FXML private RadioButton rb_key_128;
	@FXML private RadioButton rb_key_192;
	@FXML private RadioButton rb_key_256;
	@FXML private RadioButton rb_key_own;
	@FXML private TextField txt_key;
	@FXML private Label lbl_usedKey;
	
	@FXML private RadioButton rb_mode_cbc;
	@FXML private RadioButton rb_mode_ecb;

	@Override
	public void initialize(URL arg0, ResourceBundle arg1) {
		txt_initalVector.textProperty().addListener(new ChangeListener<String>() {
			@Override
			public void changed(ObservableValue<? extends String> observable, String oldValue, String newValue) {
				if(newValue.length() == 16) {
					txt_initalVector.setStyle("-fx-text-box-border: green;"
							+ "-fx-focus-color: green;");
				} else {
					txt_initalVector.setStyle("-fx-text-box-border: red;"
							+ "-fx-focus-color: red;");
				}
			}
		});
		txt_key.textProperty().addListener(new ChangeListener<String>() {
			@Override
			public void changed(ObservableValue<? extends String> observable, String oldValue, String newValue) {
				if(newValue.length() == 16 || newValue.length() == 24 || newValue.length() == 32) {
					txt_key.setStyle("-fx-text-box-border: green;"
							+ "-fx-focus-color: green;");
				} else {
					txt_key.setStyle("-fx-text-box-border: red;"
							+ "-fx-focus-color: red;");
				}
			}
		});
	}
	
	private File file_input;
	private File file_output;
	
	@FXML
	private void onChooseInputFile() {
		FileChooser chooser = new FileChooser();
		File file = chooser.showOpenDialog(StartAes.getPrimaryStage());
		if(file == null) {
			return;
		}
		lbl_openFile.setText(file.getAbsolutePath());
		file_input = file;
	}
	
	@FXML
	private void onChooseOutputFile() {
		FileChooser chooser = new FileChooser();
		File file = chooser.showSaveDialog(StartAes.getPrimaryStage());
		if(file == null) {
			return;
		}
		lbl_saveFile.setText(file.getAbsolutePath());
		file_output = file;
	}
	
	@FXML
	private void onEncryptClick() {
		int mode = 0;
		if(rb_mode_cbc.isSelected()) {
			mode = AESCrypt.CBC_MODE;
		} else if(rb_mode_ecb.isSelected()) {
			mode = AESCrypt.ECB_MODE;
		}

		byte[] iv = new byte[16];
		if(rb_iv_own.isSelected()) {
			String iv_txt = txt_initalVector.getText();
			if(iv_txt.length() == 16) {
				iv = iv_txt.getBytes();
			} else {
				return;
			}
		} else if(rb_iv_random.isSelected()) {
			Random random = new Random(new Date().getTime());
			random.nextBytes(iv);
		}
		lbl_usedIv.setText(new String(iv));
		
		byte[] key = null;
		if(rb_key_128.isSelected()) {
			key = new byte[16];
			Random random = new Random(new Date().getTime());
			random.nextBytes(key);
		} else if(rb_key_192.isSelected()) {
			key = new byte[24];
			Random random = new Random(new Date().getTime());
			random.nextBytes(key);
		} else if(rb_key_256.isSelected()) {
			key = new byte[32];
			Random random = new Random(new Date().getTime());
			random.nextBytes(key);
		} else if(rb_key_own.isSelected()) {
			String txt = txt_key.getText();
			if(txt.length() == 16 || txt.length() == 16 || txt.length() == 32) {
				key = txt.getBytes();
			}
		}
		lbl_usedKey.setText(new String(key));
		
		AESCrypt aes = null;
		try {
			aes = new AESCrypt(key, iv, mode);
		} catch (InvalidArgumentException e) {
			e.printStackTrace();
		}
		
		if(rb_process_file.isSelected()) {
			if(file_input != null && file_output != null) {
				try {
					aes.streamEncrypt(new FileInputStream(file_input), new FileOutputStream(file_output));
				} catch (FileNotFoundException e) {
					e.printStackTrace();
				}
			}
		} else if(rb_process_text.isSelected()) {
			String txt = txta_input.getText();
			aes.setText(txt.getBytes());
			aes.encrypt();
			txta_output.setText(new String(aes.getText()));
		}
	}
	
	@FXML
	private void onDecryptClick() {
		
	}
	
}

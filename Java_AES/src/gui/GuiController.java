package gui;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Observable;
import java.util.Random;
import java.util.ResourceBundle;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.stage.FileChooser;
import aes.AESCrypt;
import aes.AESCrypt.InvalidArgumentException;
import application.StartAes;


public class GuiController extends Observable implements Initializable {
	
	@FXML private Label lbl_encryptedFile;
	@FXML private Label lbl_decryptedFile;	
	
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
	
	@FXML private AnchorPane anchor_diagram;
	
	private BarChart<String, Number> chart;
	private CategoryAxis bytes = new CategoryAxis();
	private NumberAxis count = new NumberAxis();

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
		
		chart = new BarChart<String, Number>(bytes, count);
		AnchorPane.setTopAnchor(chart, 0.0);
		AnchorPane.setLeftAnchor(chart, 0.0);
		AnchorPane.setRightAnchor(chart, 0.0);
		AnchorPane.setBottomAnchor(chart, 0.0);
		anchor_diagram.getChildren().add(chart);
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
		lbl_decryptedFile.setText(file.getAbsolutePath());
		file_input = file;
	}
	
	@FXML
	private void onChooseOutputFile() {
		FileChooser chooser = new FileChooser();
		File file = chooser.showSaveDialog(StartAes.getPrimaryStage());
		if(file == null) {
			return;
		}
		lbl_encryptedFile.setText(file.getAbsolutePath());
		file_output = file;
	}
	
	@FXML
	private void onEncryptClick() {
		process(true);
	}
	
	@FXML
	private void onDecryptClick() {
		process(false);
	}
	
	private void process(boolean encrypt) {
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
		
		if(file_input != null && file_output != null) {
			try (FileInputStream in = new FileInputStream(file_input); FileOutputStream out = new FileOutputStream(file_output);) {
				if(encrypt) {
					aes.streamEncrypt(in, out);
				} else {
					aes.streamDecrypt(in, out);
				}
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		makeDiagram(aes);
	}
	
	private void makeDiagram(AESCrypt aes) {
		chart.getData().clear();
		
		XYChart.Series<String, Number> original = new XYChart.Series<String, Number>();
		original.setName("Original");
		XYChart.Series<String, Number> cipher = new XYChart.Series<String, Number>();
		cipher.setName("Cipher");
		
		if(aes != null) {
			List<Byte> bytes = new ArrayList<Byte>(aes.getOrigFreq().keySet());
			Collections.sort(bytes);
			for(Byte b : bytes) {
				original.getData().add(new XYChart.Data<String, Number>((b < 0 ? 256 + b : b)+"", aes.getOrigFreq().get(b)));
			}
			bytes = new ArrayList<Byte>(aes.getCiphFreq().keySet());
			Collections.sort(bytes);
			for(Byte b : bytes) {
				cipher.getData().add(new XYChart.Data<String, Number>((b < 0 ? 256 + b : b)+"", aes.getCiphFreq().get(b)));
			}
		} else {
			System.err.println("aes is null");
		}
		chart.getData().add(original);
		chart.getData().add(cipher);
	}
	
//	private Map<Byte, Integer> generateRandomHashMap() {
//		HashMap<Byte, Integer> map = new HashMap<Byte, Integer>();
//		Random random = new Random(new Date().getTime());
//		for(byte b=0; b>=0; ++b) {
//			map.put(b, random.nextInt(1000));
//		}
//		return map;
//	}
	
}

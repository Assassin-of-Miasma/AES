package gui;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.Observable;
import java.util.ResourceBundle;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.stage.FileChooser;
import aes.AESCrypt;
import aes.AESCrypt.InvalidArgumentException;
import application.RandomString;
import application.StartAes;

public class GuiController extends Observable implements Initializable {

	@FXML private Label lbl_outputFile;
	@FXML private Label lbl_inputFile;	
	
	@FXML private RadioButton rb_iv_random;
	@FXML private RadioButton rb_iv_own;
	@FXML private TextField txt_initalVector;
	
	@FXML private RadioButton rb_key_128;
	@FXML private RadioButton rb_key_192;
	@FXML private RadioButton rb_key_256;
	@FXML private RadioButton rb_key_own;
	@FXML private TextField txt_key;
	
	@FXML private RadioButton rb_mode_cbc;
	@FXML private RadioButton rb_mode_ecb;
	
	@FXML private AnchorPane anchor_diagram;
	
	private LineChart<Number, Number> chart;
	private NumberAxis bytes = new NumberAxis();
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
		
		chart = new LineChart<Number, Number>(bytes, count);
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
		lbl_inputFile.setText(file.getAbsolutePath());
		file_input = file;
	}
	
	@FXML
	private void onChooseOutputFile() {
		FileChooser chooser = new FileChooser();
		File file = chooser.showSaveDialog(StartAes.getPrimaryStage());
		if(file == null) {
			return;
		}
		lbl_outputFile.setText(file.getAbsolutePath());
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
		if(file_output == null || file_input == null) {
			System.err.println("No files chosen.");
		}
		
		int mode = 0;
		if(rb_mode_cbc.isSelected()) {
			mode = AESCrypt.CBC_MODE;
		} else if(rb_mode_ecb.isSelected()) {
			mode = AESCrypt.ECB_MODE;
		}

		byte[] iv = null;
		if(rb_iv_own.isSelected()) {
			String iv_txt = txt_initalVector.getText();
			if(iv_txt.length() == 16) {
				iv = iv_txt.getBytes();
			}
		} else if(rb_iv_random.isSelected()) {
			iv = new RandomString(16).nextString().getBytes();
		}
		
		byte[] key = null;
		if(rb_key_128.isSelected()) {
			key = new RandomString(16).nextString().getBytes();
		} else if(rb_key_192.isSelected()) {
			key = new RandomString(24).nextString().getBytes();
		} else if(rb_key_256.isSelected()) {
			key = new RandomString(32).nextString().getBytes();
		} else if(rb_key_own.isSelected()) {
			String txt = txt_key.getText();
			key = txt.getBytes();
		}
		
		AESCrypt aes = null;
		if(mode == AESCrypt.CBC_MODE) {
			try {
				aes = new AESCrypt(key, iv);
			} catch (InvalidArgumentException e) {
				System.err.println(e.getMessage());
			}
		} else {
			try {
				aes = new AESCrypt(key);
			} catch (InvalidArgumentException e) {
				System.err.println(e.getMessage());
			}
		}
		
		if(aes != null && file_input != null && file_output != null) {
			try (FileInputStream in = new FileInputStream(file_input); FileOutputStream out = new FileOutputStream(file_output);) {
				if(encrypt) {
					aes.streamEncrypt(in, out);
					System.out.println("Encryption succeeded");
				} else {
					aes.streamDecrypt(in, out);
					System.out.println("Encryption succeeded");
				}
				txt_initalVector.setText(new String(iv));
				txt_key.setText(new String(key));
				makeDiagram(aes);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			System.err.println("Operation failed");
		}
	}
	
	private void makeDiagram(AESCrypt aes) {
		if(aes != null) {
			chart.getData().clear();
			
			XYChart.Series<Number, Number> original = new XYChart.Series<Number, Number>();
			original.setName("Original");
			XYChart.Series<Number, Number> cipher = new XYChart.Series<Number, Number>();
			cipher.setName("Cipher");
			
			for(int b : aes.getOrigFreq().keySet()) {
				original.getData().add(new XYChart.Data<Number, Number>(b, aes.getOrigFreq().get(b)));
			}
			for(int b : aes.getCiphFreq().keySet()) {
				cipher.getData().add(new XYChart.Data<Number, Number>(b, aes.getCiphFreq().get(b)));
			}
			chart.getData().add(original);
			chart.getData().add(cipher);
		} else {
			System.err.println("Could not create Diagram");
		}
	}
	
	@FXML
	private void switchIo() {
		File tmp = file_input;
		file_input = file_output;
		file_output = tmp;
		if(file_input != null) {
			lbl_inputFile.setText(file_input.getAbsolutePath());
		} else {
			lbl_inputFile.setText("-");
		}
		if(file_output != null) {
			lbl_outputFile.setText(file_output.getAbsolutePath());
		} else {
			lbl_outputFile.setText("-");
		}
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

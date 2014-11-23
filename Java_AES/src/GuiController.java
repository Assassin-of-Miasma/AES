import java.io.File;
import java.net.URL;
import java.util.Observable;
import java.util.ResourceBundle;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Toggle;
import javafx.scene.control.ToggleGroup;
import javafx.stage.FileChooser;


public class GuiController extends Observable implements Initializable {
	
	@FXML private Label lbl_openFile;
	@FXML private Label lbl_saveFile;
	@FXML private ToggleGroup group_keyLength;

	@Override
	public void initialize(URL arg0, ResourceBundle arg1) {
		group_keyLength.selectedToggleProperty().addListener(new ChangeListener<Toggle>(){
		    public void changed(ObservableValue<? extends Toggle> ov, Toggle old_toggle, Toggle new_toggle) {
		    	RadioButton rbtn_keyLength = (RadioButton) new_toggle;
		    	int keyLength = Integer.parseInt(rbtn_keyLength.getText());
		    	System.out.println(keyLength);
	        }
		});
	}
	
	@FXML
	private void onChooseLoadFile() {
		FileChooser chooser = new FileChooser();
		File file = chooser.showOpenDialog(StartAes.getPrimaryStage());
		lbl_openFile.setText(file.getAbsolutePath());
	}
	
	@FXML
	private void onChooseSaveFile() {
		FileChooser chooser = new FileChooser();
		File file = chooser.showSaveDialog(StartAes.getPrimaryStage());
		lbl_saveFile.setText(file.getAbsolutePath());
	}
	
}

import java.net.URL;
import java.util.ResourceBundle;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;


public class GuiController implements Initializable {
	
	@FXML private Button btn_test;

	@Override
	public void initialize(URL arg0, ResourceBundle arg1) {
		// TODO Auto-generated method stub
		
	}
	
	@FXML
	private void onBtnClick() {
		System.out.println("GuiController.onBtnClick()");
	}
	
}

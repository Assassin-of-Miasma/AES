import java.io.IOException;
import java.net.URL;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;


public class StartAes extends Application {

	private static Stage primaryStage;	
	
	@Override
	public void start(Stage primaryStage) throws Exception {
		try {
//			primaryStage.getIcons().add(new Image("application/gui/icon.png"));
			primaryStage.setTitle("League of Legends - Tools");
			primaryStage.setOnCloseRequest(new EventHandler<WindowEvent>() {
				@Override
				public void handle(WindowEvent arg0) {
					Platform.exit();
				}
			});
			setScene(primaryStage, new GuiController());
			primaryStage.show();
		} catch (Exception e) {
			e.printStackTrace();
		}
		StartAes.primaryStage = primaryStage;
	}
	
	public static Stage getPrimaryStage() {
		return primaryStage;
	}
	
	public static void setScene(Initializable initializable) {
		setScene(primaryStage, initializable);
	}
	
	public static void setScene(Stage stage, Initializable initializable) {
		try {
			String name = initializable.getClass().getSimpleName();
			URL url = initializable.getClass().getResource(name.replace("Controller", "")+".fxml");
//			ResourceBundle bundle = ResourceBundle.getBundle("application.resources.language", Locale.getDefault());
//			Parent root = FXMLLoader.load(url, bundle);
			Parent root = FXMLLoader.load(url);
			Scene scene = new Scene(root);
//			scene.getStylesheets().add("application/gui/style.css");
			stage.setScene(scene);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		launch(args);
	}

}

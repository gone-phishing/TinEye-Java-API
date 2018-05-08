import java.io.*;
import tineye.api.TinEyeApiRequest;

/**
 * @author : Ritesh Kumar Singh
 **/
class Main {

	private static String PUBLIC_KEY = "";
	private static String PRIVATE_KEY = "";
	private static int LIMIT = 10;
	private static int OFFSET = 0;
	
	public static void main(String[] args) {

		TinEyeApiRequest tinEyeApiRequest = new TinEyeApiRequest("https://api.tineye.com/rest/", PUBLIC_KEY, PRIVATE_KEY);
		
		apiSearchResult = tinEyeApiRequest.requestURLSearch("search", "https://tineye.com/images/meloncat.jpg", LIMIT, OFFSET);
		System.out.println(apiSearchResult.toString());
	}
}
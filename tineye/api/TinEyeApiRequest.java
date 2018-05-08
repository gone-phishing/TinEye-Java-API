package tineye.api;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

/**
 * @author : Ritesh Kumar Singh
 **/

public class TinEyeApiRequest {
	
	private static final Logger logger = Logger.getLogger(TinEyeApiRequest.class);

    private final String apiURL;
    private final String publicKey;
    private final String privateKey;
    private final String USER_AGENT = "Mozilla/5.0";
    private final int MIN_NONCE_LENGTH = 24;
    private final int MAX_NONCE_LENGTH = 128;
    private final String nonceAllowableChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRTSUVWXYZ0123456789-_=.,*^";

    /**
     * Constructor with single parameter which in turn initializes the 3 parameter constructor
     * @param apiURL : The API end point for TinEye services
     * @throws TinEyeApiException : Throws exception from the underlying constructor
     */
	public TinEyeApiRequest(String apiURL) throws TinEyeApiException {
		this(apiURL, null, null);
	}
	
	/**
	 * Constructor with 3 parameters to initialize member variables in the class
	 * @param apiURL : The API end point for TinEye services 
	 * @param publicKey : Public key obtained from buying a paid search bundle
	 * @param privateKey : Private key obtained from buying a paid search bundle
	 * @throws TinEyeApiException : Thrown if API end point does not ends with /rest/
	 */
	public TinEyeApiRequest(String apiURL, String publicKey, String privateKey) throws TinEyeApiException {
		// All API URLs have to end with /rest/ or else the URL is incorrect.
        if (!apiURL.endsWith("/rest/")) {
            throw new TinEyeApiException("The API URL '" + apiURL + "' must end with /rest/");
        }
		this.apiURL = apiURL;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}
	
	/**
	 * Execute TinEye search by image URL method
	 * @param method : 'search' api method to search using an image url 
	 * @param searchURL : URL of the image to be used for search
	 * @param limit : Limit on number of results to match
	 * @param offset : Specify initial offset for the results
	 * @return Response from TinEye server post API execution
	 * @throws Exception Throws exceptions generated from underlying methods either to be captured at later stages or stop execution
	 */
	public JSONObject requestURLSearch(String method, String searchURL, int limit, int offset) throws Exception {
		Map<String,Object> params = new LinkedHashMap<>();
		// Parameter keys need to be put in alphabetically sorted order for the output of HMAC signing process
		// to be in accordance with TinEye API expectations. Refer to this link for more details:
		// https://services.tineye.com/developers/tineyeapi/authentication.html#signing-process
		params.put("image_url", searchURL);
		params.put("limit", limit);
		params.put("offset", offset);
		params.put("order", "desc");
        params.put("sort", "score");
        
		StringBuilder postData = new StringBuilder();
        for (Map.Entry<String,Object> param : params.entrySet()) {
            if (postData.length() != 0) postData.append('&');
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }
        String requestUrl= signGetRequestParams(method, postData.toString());
        return sendGet(requestUrl);
	}
	
	/**
	 * Calculates Nonce, HMAC Signature and request URL values 
	 * @param method : API method to execute like 'search', 'count' 'ping'
	 * @param params : Alphabetically sorted query params list as per API specification
	 * @return Request URL with params to be used for issuing GET requests
	 * @throws Exception
	 */
	private String signGetRequestParams(String method, String params) throws Exception{
		String nonce = generateNonce(this.MIN_NONCE_LENGTH + 50);
		String date = generateDate();
		String apiSignature = generateApiSignature(method, nonce, date, params);
		return generateRequestURL(method, nonce, date, apiSignature, params);
	}
	
	/**
	 * Generate the GET request url string as per API specification
	 * @param method : API method to execute like 'search', 'count' 'ping'
	 * @param nonce : A one time unique string used to prevent Man in the middle attack by reusing the API call if captured by a network sniffer tool
	 * @param date : An integer string that should be within 15 mins of current server time or will throw a 401 issue
	 * @param apiSignature : Hex encoded HMAC signed data
	 * @param params : Alphabetically sorted query params list as per API specification
	 * @return Request URL with params to be used for issuing GET requests
	 */
	private String generateRequestURL(String method, String nonce, String date, String apiSignature, String params) {
		String baseUrl = this.apiURL + method + '/';
		return baseUrl + "?api_key=" + this.publicKey + "&date=" + date + "&nonce=" + nonce + "&api_sig=" + apiSignature + "&" + params;
	}
	
	/**
	 * Generate one time unique string used to prevent Man in the middle attack by reusing the API call 
	 * if captured by a network sniffer tool
	 * @param nonceLength : Length of the nonce string to be generated.
	 * @return : Randomly generated nonce string
	 * @throws Exception : Throws nonce length out of range exception if it outside the defined min and max length
	 */
	private String generateNonce(int nonceLength) throws Exception{

		  if (((nonceLength < this.MIN_NONCE_LENGTH) || (nonceLength > this.MAX_NONCE_LENGTH))) {
		    throw new TinEyeApiException("Nonce length must be an int between " + this.MIN_NONCE_LENGTH + " and " + this.MAX_NONCE_LENGTH);
		  }

		  String nonce = "";

		  for(int i = 0; i < nonceLength; i ++) {
			  int randomCharLocation = (int) Math.floor(Math.random() * this.nonceAllowableChars.length());
			  nonce += this.nonceAllowableChars.charAt(randomCharLocation);
		  }

		  return nonce;
	}
	
	/**
	 * Get the current system date 
	 * @return An Integer string representing current system date
	 */
	private String generateDate() {
		return "" + (new Date().getTime() / 1000);
	}
	
	/**
	 * Generate the string to be signed by HMAC in accordance to TinEye API specifications
	 * @param method : API method to execute like 'search', 'count' 'ping'
	 * @param nonce : A one time unique string used to prevent Man in the middle attack by reusing the API call if captured by a network sniffer tool
	 * @param date : An integer string that should be within 15 mins of current server time or will throw a 401 issue
	 * @param params : Alphabetically sorted query params list as per API specification
	 * @return : Hex encoded HMAC signed data
	 * @throws Exception Passes forward the exceptions generated from underlying functions
	 */
	private String generateApiSignature(String method, String nonce, String date, String params) throws Exception {
		String httpVerb = "GET";
		String requestUrl = this.apiURL + method + '/';
		String toSign = (this.privateKey + httpVerb + date + nonce + requestUrl + params);
		return generateHMACSignature(toSign);
	}
	
	/**
	 * Generating hex encoded HMAC signatures encrypted using SHA-256
	 * @param toSign : String data to sign using HMAC
	 * @return : Hex encoded HMAC signed data
	 * @throws Exception : Throws exceptions like MalformedKeyException or encryption exceptions
	 */
	private String generateHMACSignature(String toSign) throws Exception {
		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		SecretKeySpec secret_key = new SecretKeySpec(this.privateKey.getBytes("UTF-8"), "HmacSHA256");
		sha256_HMAC.init(secret_key);

		return Hex.encodeHexString(sha256_HMAC.doFinal(toSign.getBytes("UTF-8")));
	}
	
	/**
	 * Send GET requests to the specified request URL
	 * @param requestURL : The URI encoded string to send GET requests
	 * @return : JSON response from the server
	 * @throws Exception : Throws IOException, URLMalformedException and a few more
	 */
	private JSONObject sendGet( String requestURL) throws Exception {
		
		URL obj = new URL(requestURL);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional: default is GET
		con.setRequestMethod("GET");

		//add request header
		con.setRequestProperty("User-Agent", USER_AGENT);

		// Display the url on console
		//System.out.println("\nSending 'GET' request to URL : " + requestURL + "\n");
		

		JSONObject responseJSON = null;
		try {
			int responseCode = con.getResponseCode();
			BufferedReader in;
			if(200 <= responseCode && responseCode <= 299) {
				in = new BufferedReader(new InputStreamReader(con.getInputStream()));
			}
			else {
				in = new BufferedReader(new InputStreamReader(con.getErrorStream()));
			}
			
			String inputLine;
			StringBuffer response = new StringBuffer();
	
			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			in.close();

			// print result
			System.out.println(response.toString());
			responseJSON = (JSONObject)JSONSerializer.toJSON(response.toString());
		}
        catch (JSONException je)
        {
            logger.error("Got exception converting response to JSON: " + je.toString());
            throw je;
        }
		catch(IOException iex) {
			iex.printStackTrace();
		}
        return responseJSON;
	}
}

package mainClasses;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.StringTokenizer;

import javax.crypto.spec.SecretKeySpec;

import utils.EncDecUtils;
import utils.EndpointDetails;
import utils.TimestampUtils;

public class TGS_R1 {
	private static String IP = "localhost";
	private static int PORT = 9091;
	private static SecretKeySpec TGS_AS_K;

	// Contains each known server belonging to this realm, as well as their
	// respective secret key shared with the TSG of that realm.
	// It's assumed 1 TGS per realm, but that isn't always true IRL
	private static Map<EndpointDetails, SecretKeySpec> knownServicies = new HashMap<EndpointDetails, SecretKeySpec>();

	private static String currentUser;
	private static EndpointDetails requestedService;

	public static void main(String args[]) throws Exception {

		setup();

		ServerSocket serverSocket = null;
		try {
			serverSocket = new ServerSocket(PORT);
			System.out.println("R1: Server is running...");

			while (true) {

				// Accept incoming connection
				Socket clientSocket = serverSocket.accept();
				System.out.println("\n R1: Client has connected!");

				BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
				PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

				handler(clientSocket, in, out);

			}
		} catch (IOException e) {
			System.out.println("R1: Server error: " + e.getMessage());
		} finally {
			if (serverSocket != null) {
				try {
					serverSocket.close();
				} catch (IOException e) {
					System.out.println("R1: Error while attempting to close the server socket " + e.getMessage());
				}
			}
		}
	}// end main

	private static void handler(Socket clientSocket, BufferedReader in, PrintWriter out) throws IOException {

		String req, res;
		while ((req = in.readLine()) != null) {
			// System.out.println("R1: received message: " + req + "\n");

			try {
				res = step4(req);
				out.println(res);

			} catch (Exception e) {
				e.printStackTrace();
			}

		} // end while

		in.close();
		out.close();
		clientSocket.close();
	}

	private static void setup() throws Exception {

		TGS_AS_K = EncDecUtils.generateKey(EncDecUtils.hashSHA256("KERBEROS_R1"));
		knownServicies.put(new EndpointDetails("luckyNumbers", "localhost", 1001),
				EncDecUtils.generateKey(EncDecUtils.hashSHA256("KERBEROS_LUCKYNUMBERS")));
		knownServicies.put(new EndpointDetails("randomFacts", "localhost", 1001),
				EncDecUtils.generateKey(EncDecUtils.hashSHA256("KERBEROS_RANDOMFACTS")));

	}

	private static String step4(String message) throws GeneralSecurityException, ParseException {

		StringTokenizer st = new StringTokenizer(message, "||");

		String rs = st.nextToken();
		boolean found = false;
		for (EndpointDetails e : knownServicies.keySet()) {
			if (e.name.equals(rs)) {
				requestedService = e;
				found = true;
			}
		}
		if (!found) {
			System.out.println("R1: ERROR! Could not find the requested server in this realm");
			throw new GeneralSecurityException();
		}

		// Retrieve data from bigCipherText
		String bigCipherText = st.nextToken();
		String bigPlainText = EncDecUtils.decrypt(bigCipherText, TGS_AS_K);
		System.out.println("R1: BigCipher has been decrypted to " + bigPlainText);

		StringTokenizer bct = new StringTokenizer(bigPlainText, "||");
		byte[] keyBytes = HexFormat.of().parseHex(bct.nextToken());
		SecretKeySpec TGS_C_K = new SecretKeySpec(keyBytes, "AES");
		System.out.println("R1: I will use the following key to communicate with C: " + TGS_C_K);
		currentUser = bct.nextToken();
		Date bigDate = TimestampUtils.fromTimestampToDate(bct.nextToken());
		int maxDelta = Integer.parseInt(bct.nextToken());

		// Retrieve data from smolCipherText
		String smolCipherText = st.nextToken();
		String smolPlainText = EncDecUtils.decrypt(smolCipherText, TGS_C_K);
		System.out.println("R1: SmolCipher has been decrypted to " + smolPlainText);

		StringTokenizer sct = new StringTokenizer(smolPlainText, "||");
		if (!currentUser.equals(sct.nextToken())) {
			System.out.println("R1: Mismatch between userIDs received");
			throw new GeneralSecurityException();
		} else {
			System.out.println(
					"R1: A match has been found between what Client and AS have assessed. Proceeding in the protocol...");
		}
		Date smolDate = TimestampUtils.fromTimestampToDate(sct.nextToken());

		if (!TimestampUtils.checkBetweenTimestamp(smolDate, bigDate, maxDelta)) {
			throw new GeneralSecurityException();
		}

		SecretKeySpec S_C_K = EncDecUtils
				.generateKey(EncDecUtils.hashSHA256(new String(EncDecUtils.getTrueRandom(16))));
		System.out.println("\nR1: Client and Service will communicate using the key: " + S_C_K.toString());
		String hexKey = HexFormat.of().formatHex(S_C_K.getEncoded());

		String timestamp = TimestampUtils.getCurrentTimestamp();
		String innerPlainText = hexKey + "||" + currentUser + "||" + timestamp + "||" + maxDelta;
		String innerCipherText = EncDecUtils.encrypt(innerPlainText, knownServicies.get(requestedService));
		String outerPlainText = hexKey + "||" + requestedService.toString() + "||" + timestamp + "||" + maxDelta + "||"
				+ innerCipherText;
		String outerCipherText = EncDecUtils.encrypt(outerPlainText, TGS_C_K);
		return outerCipherText;
	}

}

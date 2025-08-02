package mainClasses;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.StringTokenizer;

import javax.crypto.spec.SecretKeySpec;

import utils.EncDecUtils;
import utils.EndpointDetails;
import utils.TimestampUtils;

public class AuthServer {
	private static String IP = "localhost"; // <- if you change this, also change the same variable in the client
	private static int PORT = 9090; // <- if you change this, also change the same variable in the client

	/*
	 * This is the threshold used to deem invalid a message. If the difference
	 * between timestamps is greater than `maxDelta`, then the message is considered
	 * invalid.
	 */
	private static int maxDelta = 150; // expressed in seconds

	// Contains (TGS_Server, TGS_AS_Key) for each known TGS Server.
	// TGS_AS_K is the secret cryptographic key between that TGS server and the AS
	// It is assumed 1 realm <-> 1 TGS
	private static Map<EndpointDetails, SecretKeySpec> knownRealms = new HashMap<EndpointDetails, SecretKeySpec>();

	// Contains the (userID, H(password)) for every known user
	private static Map<String, String> knownUsers = new HashMap<String, String>();

	private static String currentUser;
	private static EndpointDetails requestedRealm;

	public static void main(String args[]) throws Exception {

		setup(); // create some users, keys and realms

		ServerSocket serverSocket = null;
		try {
			serverSocket = new ServerSocket(PORT);
			System.out.println("AS: Server is running...");

			while (true) {

				// Accept incoming connection
				Socket clientSocket = serverSocket.accept();
				System.out.println("\n AS: Client has connected!");

				BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
				PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

				handler(clientSocket, in, out);

			}
		} catch (IOException e) {
			System.out.println("AS: Server error: " + e.getMessage());
		} finally {
			if (serverSocket != null) {
				try {
					serverSocket.close();
				} catch (IOException e) {
					System.out.println("AS: Error while attempting to close the server socket " + e.getMessage());
				}
			}
		}
	}// end main

	private static void handler(Socket clientSocket, BufferedReader in, PrintWriter out) throws IOException {
		String req, res;

		while ((req = in.readLine()) != null) {
			System.out.println("AS: received message: " + req);
			StringTokenizer st = new StringTokenizer(req, "||");

			try {
				// Receive the step 1 and check it
				if (!securityChecks(st)) {
					res = "ERROR";
					out.println(res);
					break;
				}

				res = step2();
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

		// Adding some users
		knownUsers.put("Giorgio", EncDecUtils.hashSHA256("emerald"));
		knownUsers.put("Samuele", EncDecUtils.hashSHA256("dipende"));
		knownUsers.put("admin", EncDecUtils.hashSHA256("admin"));

		// Creating some TGS Servers
		EndpointDetails dR1 = new EndpointDetails("R1", "localhost", 9091);
		EndpointDetails dR2 = new EndpointDetails("R2", "localhost", 9092);
		EndpointDetails dRU = new EndpointDetails("RUNIBO", "localhost", 9093);

		// Registering some Realms
		/*
		 * These keys aren't created starting from random values, given the TGServers
		 * must be able to derive the same key. Alternatively, the keys derived here
		 * should be shared live with the TGServers entities
		 */
		knownRealms.put(dR1, EncDecUtils.generateKey(EncDecUtils.hashSHA256("KERBEROS_R1")));
		knownRealms.put(dR2, EncDecUtils.generateKey(EncDecUtils.hashSHA256("KERBEROS_R2")));
		knownRealms.put(dRU, EncDecUtils.generateKey(EncDecUtils.hashSHA256("KERBEROS_RUNIBO")));
	}

	private static boolean securityChecks(StringTokenizer st) throws Exception {

		// Client has sent: IDuser || IDrealm || T

		if (st.countTokens() != 3) {
			System.out.println("AS: Too few tokens");
			return false;
		}

		String u = st.nextToken();
		if (!knownUsers.containsKey(u)) {
			System.out.println("AS: User not found");
			return false;
		}

		String r = st.nextToken();
		boolean found = false;
		for (EndpointDetails stg : knownRealms.keySet()) {
			if (stg.name.equals(r)) {
				found = true;
				requestedRealm = stg;
				break;
			}
		}
		if (!found) {
			System.out.println("AS: Realm not found");
			return found;
		}

		Date deformattedDate = TimestampUtils.fromTimestampToDate(st.nextToken());
		TimestampUtils.checkTimestamp(deformattedDate, 600);
		currentUser = u;
		return true;
	}

	private static String step2() throws NoSuchAlgorithmException, GeneralSecurityException {
		SecretKeySpec TGS_C_K = EncDecUtils
				.generateKey(EncDecUtils.hashSHA256(new String(EncDecUtils.getTrueRandom(16))));
		System.out.println("AS: TGS_C_K is: " + TGS_C_K.toString());
		String hexKey = HexFormat.of().formatHex(TGS_C_K.getEncoded());

		String timestamp = TimestampUtils.getCurrentTimestamp();
		String innerPlainText = hexKey + "||" + currentUser + "||" + timestamp + "||" + maxDelta;
		String innerCipherText = EncDecUtils.encrypt(innerPlainText, knownRealms.get(requestedRealm));
		String outerPlainText = hexKey + "||" + requestedRealm.toString() + "||" + timestamp + "||" + maxDelta + "||"
				+ innerCipherText;

		SecretKeySpec userKey = EncDecUtils.generateKey(knownUsers.get(currentUser));
		System.out.println("AS: user key is: " + userKey.toString());
		String outerCipherText = EncDecUtils.encrypt(outerPlainText, userKey);

		return outerCipherText;
	}

}

package mainClasses;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.Scanner;
import java.util.StringTokenizer;

import javax.crypto.spec.SecretKeySpec;

import utils.EncDecUtils;
import utils.EndpointDetails;
import utils.TimestampUtils;

public class Client {

	private static String SIP = "localhost"; // <- update this if you update the server IP
	private static int SPORT = 9090; // <- update this if you update the server PORT

	// These variables will be set throughout the protocol
	private static String userID;
	private static String pwd;
	private static String selectedRealm;
	private static EndpointDetails TGS;
	private static String selectedServer;
	private static EndpointDetails service;
	private static SecretKeySpec TGS_C_K;
	private static SecretKeySpec S_C_K;
	private static String toCheckTimestamp;

	public static void main(String args[]) {

		try {
			Scanner scanner = new Scanner(System.in);

			// Establish connection with Authentication Server
			Socket socketAS = new Socket(SIP, SPORT);
			PrintWriter out = new PrintWriter(socketAS.getOutputStream(), true);
			BufferedReader in = new BufferedReader(new InputStreamReader(socketAS.getInputStream()));

			String request;
			String formattedDate = TimestampUtils.getCurrentTimestamp();

			System.out.println("C: Who are you?");
			userID = scanner.nextLine();
			System.out.println("C: To which realm would you like to connect to? (currently only R1 works)");
			selectedRealm = scanner.nextLine();

			// Create & Send step 1
			request = userID + "||" + selectedRealm + "||" + formattedDate;
			out.println(request);

			// - - - - -

			String response = in.readLine(); // Receive step 2
			out.close();
			in.close();
			socketAS.close();

			// Establish connection with TicketGatingServer
			Socket socketTGS = new Socket(TGS.IP, TGS.PORT);
			out = new PrintWriter(socketTGS.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(socketTGS.getInputStream()));

			// Create & Send step 3
			request = step3(response, scanner);
			out.println(request);

			// - - - - -

			response = in.readLine(); // Receive step 4
			out.close();
			in.close();
			socketTGS.close();

			// Establish connection with Service
			Socket socketS = new Socket(service.IP, service.PORT);
			out = new PrintWriter(socketS.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(socketS.getInputStream()));

			// Create & Send step 5
			request = step5(response, scanner);
			out.println(request);

			// - - - - -

			response = in.readLine(); // Receive step 6
			String plainText = EncDecUtils.decrypt(response, S_C_K);

			// Check if the nonce exchange was successful
			long expectedAnswer = TimestampUtils.fromTimestampToDate(toCheckTimestamp).getTime() + 1;
			if (expectedAnswer != Long.parseLong(plainText)) {
				System.out.println("C: FAILURE!\n");
				System.out.println("should be " + expectedAnswer + " instead is " + plainText);
				out.close();
				in.close();
				socketS.close();
				throw new GeneralSecurityException();
			}

			// IDENTIFICATION PROCESS COMPLETED
			out.println(
					EncDecUtils.encrypt("Greetings Service, I am client C under the command of user " + userID, S_C_K));

			interact(in, out, scanner);

			in.close();
			out.close();
			socketS.close();

		} catch (UnknownHostException e) {
			System.out.println("C: Error in establishing socket connection. " + e.getMessage());
		} catch (IOException e) {
			System.out.println("C: Error in creating socket. " + e.getMessage());
		} catch (GeneralSecurityException e) {
			System.out.println("C: Error! Decryption wasn't successful. YOU ARE NOT WHO YOU CLAIM TO BE!!");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static String step3(String response, Scanner scanner) throws GeneralSecurityException, Exception {

		System.out.println("C: Do you mind typing your password " + userID + " ?");
		pwd = scanner.nextLine();

		SecretKeySpec userKey = EncDecUtils.generateKey(EncDecUtils.hashSHA256(pwd));
		System.out.println("C: user key is: " + userKey.toString());
		String plainText = EncDecUtils.decrypt(response, userKey);
		System.out.println("C: SUCCESS! The plaintext is: " + plainText + "\n");
		StringTokenizer st = new StringTokenizer(plainText, "||");

		byte[] keyBytes = HexFormat.of().parseHex(st.nextToken());
		TGS_C_K = new SecretKeySpec(keyBytes, "AES");
		System.out.println("C: I will use the following key to communicate with TGS: " + TGS_C_K);

		String parenthesis = st.nextToken().replace("(", "").replace(")", "").replace(" ", "");
		StringTokenizer stp = new StringTokenizer(parenthesis, ",");
		TGS = new EndpointDetails(stp.nextToken(), stp.nextToken(), Integer.parseInt(stp.nextToken()));

		st.nextToken(); // timestamp
		st.nextToken(); // maxDelta
		String innerCipher = st.nextToken(); // portion encrypted with TGS_AS_K

		System.out.println("C: To which server of the realm " + selectedRealm
				+ " would you like to connect to? (currently only luckyNumbers works)");
		selectedServer = scanner.nextLine();

		String portion = userID + "||" + TimestampUtils.getCurrentTimestamp();
		String cipherPortion = EncDecUtils.encrypt(portion, TGS_C_K);
		return (selectedServer + "||" + innerCipher + "||" + cipherPortion);
	}

	private static String step5(String response, Scanner scanner) throws Exception {
		String plainText = EncDecUtils.decrypt(response, TGS_C_K);
		System.out.println("C: SUCCESS! The plaintext is: " + plainText + "\n");
		StringTokenizer st = new StringTokenizer(plainText, "||");

		byte[] keyBytes = HexFormat.of().parseHex(st.nextToken());
		S_C_K = new SecretKeySpec(keyBytes, "AES");
		System.out.println("C: I will use the following key to communicate with S: " + S_C_K);

		String parenthesis = st.nextToken().replace("(", "").replace(")", "").replace(" ", "");
		StringTokenizer stp = new StringTokenizer(parenthesis, ",");
		service = new EndpointDetails(stp.nextToken(), stp.nextToken(), Integer.parseInt(stp.nextToken()));

		st.nextToken(); // timestamp
		st.nextToken(); // maxDelta
		String innerCipher = st.nextToken(); // portion encrypted with server-specific secret key

		toCheckTimestamp = TimestampUtils.getCurrentTimestamp();
		String portion = userID + "||" + toCheckTimestamp;
		String cipherPortion = EncDecUtils.encrypt(portion, S_C_K);
		return (innerCipher + "||" + cipherPortion);
	}

	private static void interact(BufferedReader in, PrintWriter out, Scanner scanner)
			throws GeneralSecurityException, IOException {
		boolean exit = false;
		String s;

		while (!exit) {
			String message = EncDecUtils.decrypt(in.readLine(), S_C_K);
			System.out.println("C: received message \n \t" + message);

			s = scanner.nextLine();
			// Q for exit
			if (s.equals("Q"))
				exit = true;
			out.println(EncDecUtils.encrypt(s, S_C_K));

			message = EncDecUtils.decrypt(in.readLine(), S_C_K);
			System.out.println("C: received message \n \t" + message);
		}
		scanner.close();
	}
}

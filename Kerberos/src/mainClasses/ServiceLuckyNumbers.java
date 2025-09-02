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
import java.util.HexFormat;
import java.util.Random;
import java.util.StringTokenizer;

import javax.crypto.spec.SecretKeySpec;

import utils.EncDecUtils;
import utils.TimestampUtils;

public class ServiceLuckyNumbers {
	private static String IP = "localhost";
	private static int PORT = 1001;
	private static SecretKeySpec S_TGS_K;
	private static SecretKeySpec S_C_K;

	private static String currentUser;

	public static void main(String args[]) throws Exception {

		setup();

		ServerSocket serverSocket = null;
		try {
			serverSocket = new ServerSocket(PORT);
			System.out.println("LN: Server is running...");

			while (true) {

				// Accept incoming connection
				Socket clientSocket = serverSocket.accept();
				System.out.println("LN: Client has connected!");

				BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
				PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

				handler(clientSocket, in, out);

			}
		} catch (IOException e) {
			System.out.println("LN: Server error: " + e.getMessage());
		} finally {
			if (serverSocket != null) {
				try {
					serverSocket.close();
				} catch (IOException e) {
					System.out.println("LN: Error while attempting to close the server socket " + e.getMessage());
				}
			}
		}
	}// end main

	private static void handler(Socket clientSocket, BufferedReader in, PrintWriter out) throws IOException {

		String req, res;
		while ((req = in.readLine()) != null) {
			// System.out.println("LN: received message:" + req + "\n");

			try {
				res = step6(req);
				out.println(res);

				String message = EncDecUtils.decrypt(in.readLine(), S_C_K);
				System.out.println("LN: received message \n \t" + message);

				service(in, out);

			} catch (Exception e) {
				e.printStackTrace();
			}

		} // end while

		in.close();
		out.close();
		clientSocket.close();

	}

	private static void setup() throws GeneralSecurityException {
		S_TGS_K = EncDecUtils.generateKey(EncDecUtils.hashSHA256("KERBEROS_LUCKYNUMBERS"));
	}

	private static String step6(String message) throws GeneralSecurityException, ParseException {
		StringTokenizer st = new StringTokenizer(message, "||");

		// -- RETRIVE DATA + SECURITY CHECKS ON RECEIVED STEP 5

		// Retrieve data from bigCipherText
		String bigCipherText = st.nextToken();
		String bigPlainText = EncDecUtils.decrypt(bigCipherText, S_TGS_K);
		System.out.println("LN: BigCipher has been decrypted to " + bigPlainText);

		StringTokenizer bct = new StringTokenizer(bigPlainText, "||");
		byte[] keyBytes = HexFormat.of().parseHex(bct.nextToken());
		S_C_K = new SecretKeySpec(keyBytes, "AES");
		System.out.println("LN: I will use the following key to communicate with C: " + S_C_K
				+ ". See how it matches what TGS said?");
		currentUser = bct.nextToken();
		Date bigDate = TimestampUtils.fromTimestampToDate(bct.nextToken());
		int maxDelta = Integer.parseInt(bct.nextToken());

		// Retrieve data from smolCipherText
		String smolCipherText = st.nextToken();
		String smolPlainText = EncDecUtils.decrypt(smolCipherText, S_C_K);
		System.out.println("LN: SmolCipher has been decrypted to " + smolPlainText);

		StringTokenizer sct = new StringTokenizer(smolPlainText, "||");
		if (!currentUser.equals(sct.nextToken())) {
			System.out.println("LN: Mismatch between userIDs received");
			throw new GeneralSecurityException();
		} else {
			System.out.println(
					"LN: A match has been found between what Client and TGS have assessed. Proceeding in the protocol...");
		}
		Date smolDate = TimestampUtils.fromTimestampToDate(sct.nextToken());

		if (!TimestampUtils.checkBetweenTimestamp(smolDate, bigDate, maxDelta)) {
			throw new GeneralSecurityException();
		}

		// -- BEGIN STEP 6
		System.out.println("LN: conversion yiealds: " + smolDate.getTime());
		long once = smolDate.getTime() + 1;
		return EncDecUtils.encrypt(String.valueOf(once), S_C_K);

	}

	private static void service(BufferedReader in, PrintWriter out) throws GeneralSecurityException, IOException {
		Random random = new Random();
		boolean exit = false;

		while (!exit) {
			out.println(EncDecUtils.encrypt("LN: Press Enter to generate 5 lucky numbers or Q to exit", S_C_K));

			if (!EncDecUtils.decrypt(in.readLine(), S_C_K).equals("Q")) {
				String output = "Generated numbers: ";
				for (int i = 0; i < 5; i++) {
					int number = random.nextInt(100) + 1;
					output += (number + ", ");
				}
				out.println(EncDecUtils.encrypt("LN: " + output, S_C_K));
			} else {
				exit = true;
				out.println(EncDecUtils.encrypt("LN: Bye bye!", S_C_K));
			}
		}

	}

}

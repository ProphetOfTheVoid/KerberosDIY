package utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class TimestampUtils {

	private static SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy h:mm:ss a");

	public static String getCurrentTimestamp() {
		Date date = new Date();
		return sdf.format(date);
	}

	public static Date fromTimestampToDate(String formattedDate) throws ParseException {
		return sdf.parse(formattedDate);
	}

	public static boolean checkTimestamp(Date receivedDate, int threshold) {
		Date currentDate = new Date();
		long deltaSeconds = (currentDate.getTime() - receivedDate.getTime()) / 1000;
		if (deltaSeconds > threshold) {
			System.out.println("AS: This timestamp doesn't look legit");
			return false;
		} else
			return true;
	}

	public static boolean checkBetweenTimestamp(Date mostRecentDate, Date leastRecentDate, int threshold) {
		long deltaSeconds = (mostRecentDate.getTime() - leastRecentDate.getTime()) / 1000;
		if (deltaSeconds > threshold) {
			System.out.println("R1: This timestamp doesn't look legit");
			return false;
		} else
			return true;
	}
}

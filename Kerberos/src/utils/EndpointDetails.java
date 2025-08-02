package utils;

public class EndpointDetails {
	public String name;
	public String IP;
	public int PORT;

	public EndpointDetails(String name, String IP, int port) {
		this.name = name;
		this.IP = IP;
		this.PORT = port;
	}

	public String toString() {
		return "(" + name + ", " + IP + ", " + PORT + ")";
	}
}
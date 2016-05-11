import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class Security {
	public static BigInteger hash(String msg) {
		BigInteger out = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(msg.getBytes());
			out = new BigInteger(1,md.digest());

		}
		catch(Exception e){
			System.out.println("error no such algorithm");
		}
		return out;
	}
}
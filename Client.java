import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Random;

public class Client {
	public static void main(String [] args){
		
		try
		{
			System.out.println("I am the Client");
			Socket client = new Socket("localhost", 8000);
			System.out.println("Just connected to "+ client.getRemoteSocketAddress());
			ObjectOutputStream output = new ObjectOutputStream(client.getOutputStream()); 
			ObjectInputStream input = new ObjectInputStream(client.getInputStream()); 
			//Secure remote password protocol.
			int length = 3;
			//safe prime: N=2q+1, where q and N are primes, but it will take 1/2 a year to compute with big numbers
			String hex = "00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:d0:d4:ca:3c:50:0b:88:5f:e3";
			String hexString = hex.replaceAll(":","");
			BigInteger N = new BigInteger(hexString, 16);
			System.out.println("N: "+N);	
			//cyclic g, such that g is either g^1, g^2, ... , g^n where g^n=N
			BigInteger g = BigInteger.valueOf(2);	
					
			//gen random value 'a'
			Random rn = new Random();
			BigInteger a = BigInteger.valueOf(rn.nextInt(30));
			BigInteger A =  g.modPow(a, N);
						
			//write msg
			MessageObject msg = new MessageObject("I", A);
			output.writeObject(msg);
			
			//receive msg
			Object receivedMsg = input.readObject();
			String s = null;
			BigInteger B = null; 
			if(receivedMsg instanceof MessageObject){
				s =  ((MessageObject) receivedMsg).getstring();
				B = ((MessageObject)receivedMsg).getAB();
			}
			System.out.println("I reveived: B and s: "+B+" "+s);
			
			Security sec = new Security();
			//u=H(A, B)
			BigInteger u = sec.hash(A.toString()+", "+B.toString());
			BigInteger x = sec.hash(s+" ,"+"I"+"password");
			BigInteger k = sec.hash(N+", "+g);
			BigInteger S = B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N);
			BigInteger H = sec.hash(S.toString());
			
			System.out.println("S :"+S);
			
			BigInteger HN = sec.hash(N.toString());
			BigInteger Hg = sec.hash(g.toString());
			BigInteger xor = HN.xor(Hg);
			BigInteger HI = sec.hash("I");
			BigInteger M1 = sec.hash(xor.toString()+HI.toString()+s+A.toString()+B.toString());	
			//write msg
			output.writeObject(M1);
			//receive msg
			Object receivedM2 = input.readObject();
			
			BigInteger K = sec.hash(S.toString());
			BigInteger M2 = sec.hash(A.toString()+M1.toString()+K.toString());
			
			if(receivedM2.equals(M2)){
				System.out.println("M2 received. Server Confirmed - we have agreed on a commen key");
			}
		
			//cleaning up
			output.flush();
			output.close();
			input.close();
			client.close();
		}catch(IOException | ClassNotFoundException e)
		{
			e.printStackTrace();
		}
	}
}

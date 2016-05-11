import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

public class Server extends Thread{
	private ServerSocket serverSocket;
	public static void main(String [] args)
	{
		try
		{
			Thread t = new Server(8000);
			t.start();
		}catch(IOException e)
		{
			e.printStackTrace();
		}
	}
	public Server(int port) throws IOException
	{
		serverSocket = new ServerSocket(port);
	}

	public void run()
	{
		try
		{
			System.out.println("I am the Server");
			Socket server = serverSocket.accept(); //waiting for client to conncet
			System.out.println("Just connected to " + server.getRemoteSocketAddress());
			ObjectOutputStream output = new ObjectOutputStream(server.getOutputStream()); 
			ObjectInputStream input = new ObjectInputStream(server.getInputStream()); 
			
			
			//Secure remote password protocol.
			int length = 3;
			//safe prime: N=2q+1, where q and N are primes, but it will take 1/2 a year to compute with big numbers
			String hex = "00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:d0:d4:ca:3c:50:0b:88:5f:e3";
			String hexString = hex.replaceAll(":","");
			BigInteger N = new BigInteger(hexString, 16);
			System.out.println("N :"+N);	
			//cyclic g, such that g is either g^1, g^2, ... , g^n where g^n=N
			BigInteger g = BigInteger.valueOf(2);	
				
			
			//gen randomd value 'b'
			Random rn = new Random();
			BigInteger b = BigInteger.valueOf(rn.nextInt(30));
			
			//v
			String s = "salt";
			Security sec = new Security();
			BigInteger x = sec.hash(s+" ,"+"I"+"password");
			BigInteger v = g.modPow(x, N);
			BigInteger k = sec.hash(N+", "+g);
			BigInteger B = (k.multiply(v).add(g.modPow(b, N))).mod(N);			
		
			//write msg
			MessageObject msg = new MessageObject(s, B);
			output.writeObject(msg);

			//receive msg
			Object receivedMsg = input.readObject();
			String I = null;
			BigInteger A = null; 
			if(receivedMsg instanceof MessageObject){
				I =  ((MessageObject) receivedMsg).getstring();
				A = ((MessageObject)receivedMsg).getAB();
			}
			System.out.println("I received: A and I: "+A+" "+I);
			BigInteger u = sec.hash(A.toString()+", "+B.toString());
			BigInteger S =  A.multiply(v.modPow(u,N)).modPow(b,N);
			System.out.println("S :"+S);
					
			//receive msg
			Object receivedM1 = input.readObject();
			
			BigInteger HN = sec.hash(N.toString());
			BigInteger Hg = sec.hash(g.toString());
			BigInteger xor = HN.xor(Hg);
			BigInteger HI = sec.hash("I");
			BigInteger M1 = sec.hash(xor.toString()+HI.toString()+s+A.toString()+B.toString());	
			
			if(receivedM1.equals(M1)){
				System.out.println("M1 received. Client have been verified");
			}
			BigInteger K = sec.hash(S.toString());
			BigInteger M2 = sec.hash(A.toString()+M1.toString()+K.toString());
			//write msg
			output.writeObject(M2);
			//cleaning up
			output.flush();
			output.close();
			input.close();
			server.close();
		}catch(IOException | ClassNotFoundException e)
		{
			e.printStackTrace();
		}
	}
}

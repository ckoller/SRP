import java.io.Serializable;
import java.math.BigInteger;

public class MessageObject implements Serializable{
	private String string;
	private BigInteger AB;
	public MessageObject(String string, BigInteger AB){
		this.string = string;
		this.AB = AB;
	}
	public String getstring()
	{
		return string;
	}
	public BigInteger getAB()
	{
		return AB;
	}
	
}

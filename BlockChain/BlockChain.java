import java.io.*;
import java.lang.reflect.Type;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

/**
 * Hash256  method gotten from https://medium.com/programmers-blockchain/create-simple-blockchain-java-tutorial-from-scratch-6eeed3cb03fa
 *sign256 method, verifysig method , key pair method , message digest, base64 encoding and decoding  code adapted from https://condor.depaul.edu/elliott/435/hw/programs/Blockchain/BlockJ.java
 * gson string code for marshalling Linkedlist adapted from https://www.baeldung.com/gson-list 
 * uploadblock method adapted from  https://condor.depaul.edu/elliott/435/hw/programs/Blockchain/BlockInputG.java
 * work method , random seed method adapted  from https://condor.depaul.edu/elliott/435/hw/programs/Blockchain/WorkB.java
 * server , ports, worker and multicasting code adapted from https://condor.depaul.edu/elliott/435/hw/programs/Blockchain/bc.java
 * 
 * 
 */





// java -cp ".:gson-2.8.2.jar" BlockChain 0
//javac -cp "gson-2.8.2.jar" BlockChain.java 


public class BlockChain {
	
	private static final int iFNAME = 0;
	private static final int iLNAME = 1;
	private static final int iDOB = 2;
	private static final int iSSNUM = 3;
	private static final int iDIAG = 4;
	private static final int iTREAT = 5;
	private static final int iRX = 6;
	private static int numProcesses = 3;

	static int signal=0;//intial signal set to zero if 1 start multicast
	static int sent;
	static int Recieved;
	static int processId;

	static String FILENAME;
	static HashMap<Integer,PublicKey> keymap=new HashMap<>();//map process ids and public keys
	static HashMap<Integer,String> keymap2=new HashMap<>();//map process id and base64 encoded publickeys
	static PrivateKey privatekey;//store process private key
	static LinkedList<blockrecord> BLOCKCHAIN=new LinkedList<blockrecord>();//local blockchain
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		BlockChain s=new BlockChain();
		final PriorityBlockingQueue<blockrecord> queue=new PriorityBlockingQueue<>(24,new blockrecord());
		//thread safe blocking queue for production and consumption of ub blocks to be verified.
		s.run(args,queue);//call run method with command line args and queue

	}
	public void run(String[] args,PriorityBlockingQueue<blockrecord> queue) throws Exception {
		if (args.length < 1)  processId = 0;
	    else if (args[0].equals("0"))  processId = 0;
	    else if (args[0].equals("1"))  processId= 1;
	    else if (args[0].equals("2"))  processId= 2;
	    else  processId = 0;
		//accept command line argument for procecess numbe
		

		//set file to read from depending on processid
		switch(processId){
		case 1: FILENAME = "BlockInput1.txt"; break;
		case 2: FILENAME = "BlockInput2.txt"; break;
		default: FILENAME= "BlockInput0.txt"; break;
		}
		
		//set port numbers
		new Ports(processId).setPorts();
		Random rand = new Random();
	   	int randint=rand.nextInt(700 - 150) + 150;
		//gennerate public key and private key
		KeyPair pair=generateKeyPair(randint);
		//store this processes private key
		privatekey=pair.getPrivate();
		System.out.println("Process "+processId+" private key generated ");

		//start the thread for public keys , UB and blockchain server and signal start
		new Thread(new PublicKeyServer()).start();
		new Thread(new UnverifiedBlockServer(queue)).start();
		new Thread(new BlockchainServer()).start();
		new Thread(new signalstart()).start();
		
		//UPLOAD THE BLOCKS FOR PROCESS 0,1 AND 2 AND STORE IN A LINKED LIST
		LinkedList<blockrecord> UBLIST=uploadblock(FILENAME);
		//CREATE A DUMMY BLOCK
		DummyBlock(BLOCKCHAIN);
		System.out.println(" Dummy block added ");

		//WHEN PROCESS 2 IS RUNNING SEND SIGNAL TO PROCESS 1,2 TO START
		if(processId==2){
			sendsignal();//MULTICAST SIGNAL
			signal=1;
		}
		
		
		Thread.sleep(4000);
		
		if(signal==1){//WHEN 0 AND 2 HAVE RECIVED THE 1 SIGNAL  MULTICAST KEYS
			
		
		
		Thread.sleep(4000);
		multicastkeys(pair);//MULTICAST KEYS
		
		
		
		
		Thread.sleep(6000);//SLEEP THEN MULTICAST THE UNVERIFIED BLOCKS
		UnverifiedSend(UBLIST);
		
		Thread.sleep(10000);
			
		// START THE CONSUMER THREAD
		new Thread(new UnverifiedBlockConsumer(queue)).start();
			
		
		
		}
	
	}
	
	public static LinkedList<blockrecord> uploadblock(String Filename) throws Exception{
		
		
		 BufferedReader br = new BufferedReader(new FileReader(Filename));// bufferreader to open input stream from file
		 String[] tokens = new String[10];
		 String block;
		 LinkedList<blockrecord>  UBLIST= new LinkedList<blockrecord>();
		 while((block = br.readLine()) != null) {
			 
			tokens = block.split(" +");
			Thread.sleep(1001);//sleep to make different time stamps for each block
			blockrecord BR = new blockrecord();//create new block
			//token nice the block string and store the data in the block
			Date date = new Date();
			System.out.println("Timestamp: " + date+" at process "+processId);
			 BR.setTimestamp(new Date()); 
			 BR.setFname(tokens[iFNAME]);
			 BR.setLname(tokens[iLNAME]);
			 BR.setSSNum(tokens[iSSNUM]);
			 BR.setDOB(tokens[iDOB]);
			 BR.setDiag(tokens[iDIAG]);
			 BR.setTreat(tokens[iTREAT]);
			 BR.setRx(tokens[iRX]);
			 BR.setCreationId(processId);
			 UBLIST.add(BR);

			 String blockdata=BR.getBlockID();// get block id to sign data
			 MessageDigest md = MessageDigest.getInstance("SHA-256");
			 md.update (blockdata.getBytes());
			 byte byteData[] = md.digest();//get the bytes of the block digest
			 
			 StringBuffer sb = new StringBuffer();
				for (int i = 0; i < byteData.length; i++) {
				  sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));//turn the firt 16 bits to 0's
				}
				
			 String SHA256String = sb.toString();// create hash256 string
			 byte[] digitalSignature = signData(SHA256String.getBytes(),privatekey);//create a dig signature by signing the hash256 string with the private key for this process
			 
			 String SignedSHA256 = Base64.getEncoder().encodeToString(digitalSignature);// base64 encode the signature 
				//add the hash256 block id and the signed signature to the blockrecoed
			 BR.setSignedSHA(SignedSHA256);//store the signedSHA
			 BR.setSHA256String(SHA256String);//stor the sha string 
			 
		 }
		return UBLIST;
	}

//key send generates key pair 
public static KeyPair generateKeyPair(long seed) throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");
		SecureRandom rng=SecureRandom.getInstance("SHA1PRNG", "SUN");
		rng.setSeed(seed);
		generator.initialize(1024, rng);
		return generator.generateKeyPair();
	
}

//dummyblock method adds the genesis block to the blockchain for every process
public static void DummyBlock(LinkedList<blockrecord> chain) throws Exception {
	blockrecord dummyBlock=new blockrecord();
	String blockdata="Medical records block record";
	 MessageDigest md = MessageDigest.getInstance("SHA-256");
	 md.update (blockdata.getBytes());
	 byte byteData[] = md.digest();
	 
	    
	  
	StringBuffer sb = new StringBuffer();
	 for (int i = 0; i < byteData.length; i++) {
	   sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
	  }
	//produce sha 256 string then sign with pub key
	String SHA256String = sb.toString();
	byte[] digitalSignature = signData(SHA256String.getBytes(),BlockChain.privatekey);
	String SignedSHA256 = Base64.getEncoder().encodeToString(digitalSignature);
	//set all feilds
	dummyBlock.setSHA256String(SHA256String);
	dummyBlock.setSignedSHA(SignedSHA256 );
	dummyBlock.setFname("dum");
	dummyBlock.setLname("dum");
	dummyBlock.setTimestamp(new Date());
	dummyBlock.setBlockID("1");
	dummyBlock.setPreviousHash("0000");
	dummyBlock.setCreationId(processId);
	dummyBlock.setSHA256String(SHA256String);
	dummyBlock.setPreviousHash("1234455353636");
	dummyBlock.setHash("535363636363737");
	dummyBlock.setSignedSHA(SignedSHA256);
	
	
	
	chain.add(dummyBlock);//add to chain
	
	
}
/**
 * send signal method notifies all processes to change their signal from 0 to 1 in other to start the multicast of UB , keys and blockchain
 */
public void sendsignal(){
	Socket Signalsock;
	PrintStream stream;
	 
	try{
			
	for(int i=0; i< numProcesses-1; i++){// Send our public key to all servers.
		
		Signalsock = new Socket("localhost",Ports.singnalServerBase+i);//connect the socket to all the signal server ports
		stream = new PrintStream(Signalsock.getOutputStream());//prinstream to send data
		stream.write(1);//multicast the 1 signal to all the processes
		stream.flush();
		Signalsock.close();
		}
	}catch (Exception x) {x.printStackTrace ();}
	
}
/**
 * multicastkeys multicasts public keys to all processes
 */

public void multicastkeys(KeyPair pair) throws NoSuchAlgorithmException, NoSuchProviderException{ // Multicast our public key to the other processes
		Socket sock;
		PrintStream Stream;
		byte[] bytePubKey= pair.getPublic().getEncoded();
		String stringKey=Base64.getEncoder().encodeToString(bytePubKey);//encode the public keys in base 64 string
		
		Gson gson=new Gson();
		String json=gson.toJson(stringKey);//convert base 64 pubkey to gson string
		 
		try{
			
		    for(int i=0; i< numProcesses; i++){
		    
		    sock = new Socket("localhost",Ports.KeyServerPortBase+i);
			Stream = new PrintStream(sock.getOutputStream());
			Stream.write(processId);//multicast the process id
			Stream.println(json);//multicast the process  public key
			Stream.flush();
			
			sock.close();
		    }
		}catch (Exception x) {x.printStackTrace ();}
	}
	//generate a random String seed for the work algorithm
	public static String randomSeed() {
		Random random=new Random();
        int rval=random.nextInt(167777215);
        String randseed=String.format("%06x",rval &0x0ffffff);
        return randseed;
	}
	//work returns true if puzzle solved
	public static  boolean work(blockrecord record) throws NoSuchAlgorithmException, UnsupportedEncodingException , InterruptedException{
		System.out.format("Doing work.....");
		for(int i=0;i<20;i++) {
		String randSeed=randomSeed();//store random seed
		String blockdata=record.getFname()+record.getLname()+record.getBlockID()+record.getPreviousHash();//concatenate the block data prev hash of the block before 
		
		String hash=Hash256(blockdata+randSeed);//hash the concatenate block data , prev hash and rand seed
		int workNumber = 0;     
		Random r=new Random();
		Thread.sleep((r.nextInt(4) * 1000));//sleep the thread to for process cooedination so other blocks can compete
		workNumber = Integer.parseInt(hash.substring(0,4),16);
		if (!(workNumber < 20000)){  
		   //if less 20000 the puzzle is not solved
		    
		}
		if (workNumber < 20000){
		    System.out.format("%d IS less than 20,000 so puzzle solved!\n", workNumber);//if worknumber less 20000
		    System.out.println("The seed (puzzle answer) was: " + randSeed);
		    record.setSeed(randSeed);//set block seed
			record.setHash(hash);//set the block hash
		    record.setBlockdata(blockdata+randSeed);//set the block data
		   
		    
		    
		    return true;
		    
		}
		
		
		}
		return false;
		
		
	}
	//hash26 algorithm to hash the blockdata
	public static String Hash256(String blockrecord) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest digest=MessageDigest.getInstance("SHA-256");//intantize message digest with the SHA-256 algorithm
		byte[] hash = digest.digest(blockrecord.getBytes("UTF-8"));//get the bytes hash of the block 
		StringBuffer hexString = new StringBuffer();
		for (int i = 0; i < hash.length; i++) {
			String hex = Integer.toHexString(0xff & hash[i]);
			if(hex.length() == 1) hexString.append('0');
			hexString.append(hex);//turn the bytes to hexsting
		}
		return hexString.toString();
	}
	
	//method sign data signs the block id bytes with the creator processes 
	public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
	    Signature signer = Signature.getInstance("SHA1withRSA");
	    signer.initSign(key);
	    signer.update(data);
	    return (signer.sign());
	  }
	//method to verify digital signature with the process pub key and the data
	public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
	    Signature signer = Signature.getInstance("SHA1withRSA");
	    signer.initVerify(key);
	    signer.update(data);
	    
	    return (signer.verify(sig));
	  }
	  /**
	   * 
	   * @param unverifiedblocks each blockrecord in the linklist is mulicast to all processeds
	   */
	 public static void UnverifiedSend (LinkedList<blockrecord> unverifiedblocks){ 

			Socket UVBsock; //socket to  connect to all the UB ports
			blockrecord Rec;
			Random rand = new Random();
			try{
				/**
				 * use a prinstream to send the Unverified blocks to the 
				 */
			  PrintStream toServer = null; 
			   for(int i = 0; i < numProcesses; i++){

			    	for(int j=0;j<unverifiedblocks.size();j++) {
				    UVBsock = new Socket("localhost", Ports.UnverifiedBlockServerPortBase + i);
				    toServer = new PrintStream (UVBsock.getOutputStream());
				    toServer.write(processId);//send the process number for identification
				    //Thread.sleep((rand.nextInt(9) * 100)); //sleep
				    Rec=unverifiedblocks.get(j);//retrieve block from the linkedlist
				    Gson gson = new Gson();
					String json = gson.toJson(Rec);//turn the block to gson string
				    toServer.println(json); //send the json string
					sent++;
					System.out.println(sent+" BLOCKS sent");
				    toServer.flush();
				    UVBsock.close();
			    	}
				
				}
			   
			}catch (Exception x) {x.printStackTrace ();}
		    }
	 
	 public static void sendchain(LinkedList<blockrecord> chain) {
			
			Socket BCsock;
			PrintStream stream;
			Gson gson2=new Gson();
			String json2 = gson2.toJson(chain);//turn the blockchain to a json string
			try{
				
			    for(int i=0; i< numProcesses; i++){
			    
				BCsock = new Socket("localhost", Ports.BlockChainServerPortBase+i);
				stream = new PrintStream( BCsock.getOutputStream());
				stream.write(processId);//multicast process id and blockchain gson string
				stream.println(json2);
				stream.flush();
				BCsock.close();
			    }
			}catch (Exception x) {x.printStackTrace ();}
		}
	 
		// readledger method to blockchain string into a gson string
	 public static LinkedList<blockrecord> readledger(String json){
			Gson gson2=new Gson();
			Type listOfMyClassObject = new TypeToken<LinkedList<blockrecord>>() {}.getType();//get class of the generic linkedlist
			LinkedList<blockrecord> List = gson2.fromJson(json, listOfMyClassObject);
			return List;//return linkedlist
		}
	 
		

}
/**
 * port class that holds the port numbers to multicast the signal , keys , blocks and chains.
 */
class Ports{
	int pid;
	public Ports(int pid) {
		this.pid=pid;
	}
	public static int KeyServerPortBase=4710;
	public static int UnverifiedBlockServerPortBase=4820;
	public static int BlockChainServerPortBase=4930;
	public static int singnalServerBase=5110;
	
	
	public static int KeyServerPort;
	public static int UnverifiedBlockServerPort;
	public static int BlockChainServerPort;
	public static int singnalServer;
	
	
	/**
	 * set the ports depending on the processId
	 */
	public void setPorts() {
		KeyServerPort= KeyServerPortBase+pid;
		UnverifiedBlockServerPort=UnverifiedBlockServerPortBase+pid;
		BlockChainServerPort=BlockChainServerPortBase+pid;
		singnalServer=singnalServerBase+pid;
		
	}
	
}
/**
 * class block record to hold the block data
 */
class blockrecord implements Comparator<blockrecord>{
	//data feilds
	private String Fname;
	private String Lname;
	UUID uuid=UUID.randomUUID();
	private Date Timestamp;
	private String hash;
	private String previousHash;
	private String BlockID=uuid.toString();
	private String seed;
	private String SSNum;
	private String DOB;
	private String Diag;
	private String Treat;
	private String Rx;
	private String blockdata;
	private String signedSHA;
	private String SHA256String;
	private int VerificationId;
	private int creationId;
	 
	 //getters and setter methods for feilds
	 public int getCreationId() {
		return creationId;
	}

	public void setCreationId(int creationId) {
		this.creationId = creationId;
	}

	public String getSHA256String() {
		return SHA256String;
	}
	
	public void setSHA256String(String SHA256String) {
		this.SHA256String = SHA256String;
	}
	public String getSignedSHA() {
		return signedSHA;
	}
	public void setSignedSHA(String signedSHA) {
		this.signedSHA = signedSHA;
	}
	public String getBlockdata() {
		return blockdata;
	}
	public void setBlockdata(String blockdata) {
		this.blockdata = blockdata;
	}
	
	public int getVerificationId() {
		return VerificationId;
	}
	public void setVerificationId(int verificationId) {
		VerificationId = verificationId;
	}
	public String getSSNum() {
		return SSNum;
	}
	public void setSSNum(String sSNum) {
		SSNum = sSNum;
	}
	public String getDOB() {
		return DOB;
	}
	public void setDOB(String dOB) {
		DOB = dOB;
	}
	public String getDiag() {
		return Diag;
	}
	public void setDiag(String diag) {
		Diag = diag;
	}
	public String getTreat() {
		return Treat;
	}
	public void setTreat(String treat) {
		Treat = treat;
	}
	public String getRx() {
		return Rx;
	}
	public void setRx(String rx) {
		Rx = rx;
	}
	public String getSeed() {
			return seed;
	}
	public void setSeed(String seed) {
			this.seed = seed;
	}
		
	public Date getTimestamp() {
			return Timestamp;
	}
	public void setTimestamp(Date timestamp) {
			Timestamp = timestamp;
	}
	public String getHash() {
			return hash;
	}
	public void setHash(String hash) {
			this.hash = hash;
	}
	public String getPreviousHash() {
			return previousHash;
	}
	public void setPreviousHash(String previousHash) {
			this.previousHash = previousHash;
	}
	public String getBlockID() {
			return BlockID;
	}
	public void setBlockID(String blockID) {
			BlockID = blockID;
	}
	public String getFname() {
			return Fname;
	}
	
	public void setFname(String fname) {
			Fname = fname;
	}
	
	public String getLname() {
			return Lname;
	}
	
	public void setLname(String lname) {
			Lname = lname;
	}
	public int compare(blockrecord b1, blockrecord b2)
    {
     String s1 = b1.getTimestamp().toString();
     String s2 = b2.getTimestamp().toString();
     if (s1 == s2) {return 0;}
     if (s1 == null) {return -1;}
     if (s2 == null) {return 1;}
     return s1.compareTo(s2);
    }
		
		
}
class PublicKeyServer implements Runnable{
	
	public PublicKeyServer() {
		
	}

	@Override
	public void run() {
		// TODO Auto-generated method stub
		int q_len=6;
		Socket keysock;
		System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
		try{
		    ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);//open connection at keyseverport port
		    while (true) {
			keysock = servsock.accept();//block and wait for connection then accept
			new PublicKeyWorker (keysock).start(); //start the worker thread
		    }
		}catch (IOException ioe) {System.out.println(ioe);}
	    }
		
}
/**
 * This class recieves the public keys , and adds them to a hashmap with their process numbers
 */
class PublicKeyWorker extends Thread { 
    Socket keySock; //feild socket to be passed from the server
	PublicKeyWorker (Socket s) {keySock = s;
    
    } 
    public void run(){
	try{
		
	    BufferedReader Reader = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
	    
	    int pid=Reader.read();//recive the process number and the gson base 64string pub key
	    String key=Reader.readLine();

	    Gson gson=new Gson();
	    String base64key=gson.fromJson(key, String.class);//restore key to base64

	    System.out.println("Recieved process "+pid+ "  public key");
	    byte[] bytePubKey=Base64.getDecoder().decode(base64key);//decode key intro byte array
		X509EncodedKeySpec pub=new X509EncodedKeySpec(bytePubKey);
		KeyFactory keyFactory= KeyFactory.getInstance("RSA");
		PublicKey publickey=keyFactory.generatePublic(pub);//restore the public key
		BlockChain.keymap.put(pid, publickey);//add the pub key to the hashmap 
		
		BlockChain.keymap2.put(pid,base64key);//add the base64 pub key to the hash map
		System.out.println(BlockChain.keymap.get(pid));
		
		
		keySock.close(); 
		
	    } catch (IOException | NoSuchAlgorithmException x){x.printStackTrace();} catch (InvalidKeySpecException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
    }
}
class UnverifiedBlockWorker extends Thread { 
	Socket sock; 
	PriorityBlockingQueue<blockrecord> queue;//thread safe priority queue as feild 
	UnverifiedBlockWorker (Socket s,PriorityBlockingQueue<blockrecord> queue) {
		sock = s;this.queue=queue;} 
	
    
	public void run(){
	  
      try{
	BufferedReader unverifiedIn = new BufferedReader( new InputStreamReader(sock.getInputStream()));
	Gson gson = new Gson();
	int pid=unverifiedIn.read();//process number
	String block=unverifiedIn.readLine();// blockrecord gson string
	blockrecord BR =gson.fromJson(block,blockrecord.class);//convert from gson string to blockrecord
	System.out.println("Received UVB: " + BR.getTimestamp() + " " + BR.getFname()+" "+BR.getLname()+" from "+pid);
	BlockChain.Recieved++;//update the number of blocks recieved
	System.out.println(BlockChain.Recieved+" "+" recieved");
	queue.add(BR);//add the block to the queue for consumption
	sock.close(); 
      } catch (Exception x){x.printStackTrace();}
    }
	
	
  }

class UnverifiedBlockServer implements Runnable {
	PriorityBlockingQueue<blockrecord> queue;//blocking queue for production and consumption
    UnverifiedBlockServer(PriorityBlockingQueue<blockrecord> queue){
	 this.queue=queue;
    }
    public void run(){ 
        int q_len = 6; 
        Socket sock;
        System.out.println("Starting the Unverified Block Server input thread using " +
    		       Integer.toString(Ports.UnverifiedBlockServerPort));
        try{
          ServerSocket UVBServer = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);//open socket connection
          while (true) {
        	sock = UVBServer.accept(); ////block while waiting for a connection then accept the connection on the server
    	
    	new UnverifiedBlockWorker(sock,queue).start(); //start the worker thread and pass it the blocking queue as an argument
          }
        }catch (IOException ioe) {System.out.println(ioe);}
      }
    }

class BlockchainWorker extends Thread { // Class definition
    Socket sock; // Class member to be passed from the the blockserver 
    BlockchainWorker (Socket s) {sock = s;} 
    public void run(){
		
	try{
	    BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
	  
	    int pid=in.read();//accept the process number
	    String obj=in.readLine();//accept the multicasted gson blockchain string
	    Gson gson = new Gson();
	    LinkedList<blockrecord> list=BlockChain.readledger(obj);//convert gson to linked linkedlist of blockrecords
	    BlockChain.BLOCKCHAIN=list;//set local blockchain to the multicasted blockcahin
		
	    if(BlockChain.processId==0) {//if the process number is 0 write to block ledger
	    	Gson gson3 = new GsonBuilder().setPrettyPrinting().create();
	    	String json = gson3.toJson(list);
	    	try (FileWriter writer = new FileWriter("BlockchainLedger.json")) {
	    	      gson3.toJson(BlockChain.BLOCKCHAIN, writer);
	    	    } catch (IOException e) {
	    	      e.printStackTrace();
	    	    }
	    }
	
	    sock.close(); 
	} catch (IOException  x){x.printStackTrace();}
	
    }
	
}


class BlockchainServer implements Runnable {
    public void run(){
	int q_len = 6; 
	Socket chainsock;
	System.out.println("Starting the Blockchain server input thread using " + Integer.toString(Ports.BlockChainServerPort));
	try{
	    ServerSocket servsock = new ServerSocket(Ports.BlockChainServerPort, q_len);//open connection for blockchainserver
	    while (true) {
			chainsock = servsock.accept();//wait for connection
		new BlockchainWorker (chainsock).start(); 
	    }
	}catch (IOException ioe) {System.out.println(ioe);}
    }
}
class UnverifiedBlockConsumer implements Runnable {
	  PriorityBlockingQueue<blockrecord> queue; // 
	  
	  UnverifiedBlockConsumer(PriorityBlockingQueue<blockrecord> queue){
	    this.queue = queue; // pass the local PQ as a constructor argument
	  }

	  public void run(){
	   
	    blockrecord Rec;
	    System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
	    try{
			
	    	while(!queue.isEmpty()) {//while queue is not empty queue
			
	       Rec=queue.take();//remove the highest priority
		   System.out.println(Rec.getFname()+" "+Rec.getLname()+" "+Rec.getTimestamp());//print the block details 
		   
	       boolean check=idcheck(BlockChain.BLOCKCHAIN,Rec);//check that the block isnt already in chain
	       
	       if(check) {
	    	  
		       

				byte[] Signature = Base64.getDecoder().decode(Rec.getSignedSHA());// get the byte dig signature by decoding the base64 SignedSHA string in the block record
				PublicKey publickey=BlockChain.keymap.get(Rec.getCreationId());//retrieve the public key for the process that created 
				
				
				boolean verified = BlockChain.verifySig(Rec.getSHA256String().getBytes(),publickey, Signature);//verify the digital signature with the sha256 string and the pub key
				
				boolean check2=idcheck(BlockChain.BLOCKCHAIN,Rec);//check the block is already in the chain
				
				
				if(verified &&check2) {
					System.out.println("BLOCK SUCCESFULLY VERIFIED ");

					boolean check3=idcheck(BlockChain.BLOCKCHAIN,Rec);// check again incase it has been updated
					if(check3){//if not in block
						String prevHash=BlockChain.BLOCKCHAIN.get(BlockChain.BLOCKCHAIN.size()-1).getHash();//set prev hash of the blockrecord
					
					
					Rec.setPreviousHash(prevHash);//set the prev hash 
					
					
					boolean doWork=BlockChain.work(Rec);//do work and solve the puzzle

					boolean check4=idcheck(BlockChain.BLOCKCHAIN,Rec);//check the local blockchain
					if(doWork && check4)  {//if work has been done and the block not in current chain
						
						boolean check5=idcheck(BlockChain.BLOCKCHAIN,Rec);//check again
						if(check5  && Rec.getPreviousHash().equals(BlockChain.BLOCKCHAIN.get(BlockChain.BLOCKCHAIN.size()-1).getHash())){//check if the block is valid by checking if the block before's hash is equal to its prev hash
						Rec.setVerificationId(BlockChain.processId);//set the verifying method
						System.out.println(Rec.getFname()+" "+Rec.getLname()+" verified by " +Rec.getVerificationId());
						BlockChain.BLOCKCHAIN.add(Rec);//add the block to the chain
						BlockChain.sendchain(BlockChain.BLOCKCHAIN);//send the blockchain
						System.out.println(" ADDING BLOCK TO blockChain...... ");
						}else{
							System.out.println(" Already in blockChain...... ");
						}
						
						
					}
				}else{
					System.out.println(" This block is already in blockChain..... ");
				}
				
				}else {
					System.out.println("BLOCK WASNT VERIFIED");
				}
				
		      
	       }
		   
		   Thread.sleep(1500);//sleep thread to coordinate processes
		   
	       
	    	}
	    	
	      
	    }catch (Exception e) {e.printStackTrace();}
	  }
	  public boolean idcheck(LinkedList<blockrecord> chain,blockrecord record) {//method to check if the block is not in chain , RETURN TRUE
		  if(!chain.isEmpty()) {
		  for(blockrecord a:chain) {
			  if(record.getBlockID().equals(a.getBlockID())) {
				  return false;
			  }
		  }
		  }
		  return true;
	  }
	  
	}

/**
 * signal server to signify processes that two has started
 */
class signalstart implements Runnable{
	int q_len = 6;
    Socket sock;
	public void run(){
		try {
			ServerSocket servsock = new ServerSocket(Ports.singnalServer, q_len);

		while(true){
			sock = servsock.accept();
			new signalstartworker(sock).start();
		}
		} catch (Exception e) {
			e.printStackTrace();
		}
		


	}
}
/**
 * 
 */

class signalstartworker extends Thread{
	Socket sock;
	public signalstartworker(Socket sock){
		this.sock=sock;
	}
	public void run(){
		try{
			  
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			int signal=in.read();//recieve the one signal from process 2
			BlockChain.signal=signal;//set dignal to one and start system
			  
			}catch(IOException e){System.out.print(e);}
		  }
	
}




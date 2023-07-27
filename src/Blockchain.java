/*
	November 3rd 2020
	
    Blockchain.java  
	
	Steven Perry for CSC435
	
    java 1.8.0_265
	
    INSTRUCTIONS:
	
	You will need to download gson-2.8.2.jar into your classpath / compiling directory.
	
	To compile:
    javac -cp "gson-2.8.2.jar" Blockchain.java
	
	To run:
    java -cp ".;gson-2.8.2.jar" Blockchain 0
	java -cp ".;gson-2.8.2.jar" Blockchain 1
	java -cp ".;gson-2.8.2.jar" Blockchain 2
	
    Files needed to run:
    Blockchain.java
    BlockInput0.txt
	BlockInput1.txt
	BlockInput2.txt
	gson-2.8.2.jar
	
	I have also provided a blockMaster.bat, as well as a processZero.bat, processOne.bat,
	and processTwo.bat. If you run blockMaster.bat it should take care of all of the above.
	
	
    -Notes: 
    Occasionally one process crashes and I was unable to figure out why, most of the time
	it carries on without that process. For some reason this almost never happens when I run
	the program right after compiling, but happens more often after I have already fully ran 
	the program and attempt to run it again.
	
	Much of the code is taken directly from or slightly modified from programs provided by
	Clark Elliot. These programs include:
	BlockJ.java: https://condor.depaul.edu/~elliott/435/hw/programs/Blockchain/BlockJ.java
	BlockInputG.java: https://condor.depaul.edu/~elliott/435/hw/programs/Blockchain/BlockInputG.java
    bc.java: https://condor.depaul.edu/~elliott/435/hw/programs/Blockchain/bc.java
	WorkB.java: https://condor.depaul.edu/~elliott/435/hw/programs/Blockchain/WorkB.java
	
*/

//All of the import utilities
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import javax.xml.bind.DatatypeConverter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.FileReader;
import java.io.Reader;
import java.util.LinkedList;
import java.util.*;
import java.io.StringWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.io.StringReader;
import java.io.BufferedReader;
import java.text.*;

//Class for storing data on each block, most of it is directly from BlockInputG
//but I ended up adding a few more variables
class BlockRecord{
	String BlockID;
	String TimeStamp;
	String VerificationProcessID;
	String PreviousHash; 
	String Fname;
	String Lname;
	String SSNum;
	String DOB;
	String RandomSeed; 
	String WinningHash;
	String Diag;
	String Treat;
	String Rx;

	//This variable is for storing the index of a block within the blockchain
	int index;
	//This variable is for storing the signature ID
	String signedID; 
	//This variable is for storing the signature for the winning hash
	String signedWinningHash;
  
  
	public String getBlockID() {return BlockID;}
	public void setBlockID(String BID){this.BlockID = BID;}

	public String getTimeStamp() {return TimeStamp;}
	public void setTimeStamp(String TS){this.TimeStamp = TS;}

	public String getVerificationProcessID() {return VerificationProcessID;}
	public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}
  
	public String getPreviousHash() {return this.PreviousHash;}
	public void setPreviousHash (String PH){this.PreviousHash = PH;}
  
	public String getLname() {return Lname;}
	public void setLname (String LN){this.Lname = LN;}
  
	public String getFname() {return Fname;}
	public void setFname (String FN){this.Fname = FN;}
  
	public String getSSNum() {return SSNum;}
	public void setSSNum (String SS){this.SSNum = SS;}
  
	public String getDOB() {return DOB;}
	public void setDOB (String RS){this.DOB = RS;}

	public String getDiag() {return Diag;}
	public void setDiag (String D){this.Diag = D;}

	public String getTreat() {return Treat;}
	public void setTreat (String Tr){this.Treat = Tr;}

	public String getRx() {return Rx;}
	public void setRx (String Rx){this.Rx = Rx;}

	public String getRandomSeed() {return RandomSeed;}
	public void setRandomSeed (String RS){this.RandomSeed = RS;}
  
	public String getWinningHash() {return WinningHash;}
	public void setWinningHash (String WH){this.WinningHash = WH;}
  
  
	public int getIndex() {return index;}
	public void setIndex(int index){this.index = index;}
  
	public String getSignedID() {return signedID;} 
	public void setSignedID (String signedID){this.signedID = signedID;}
  
	public String getSignedWinningHash() {return signedWinningHash;}
	public void setSignedWinningHash (String signedWinningHash){this.signedWinningHash = signedWinningHash;}
  
}

//This is a class I created for storing the public keys of each process
class BlockKey {
	//This is the public key
    String key;
	//This is the PID
    int id;
    public String getKey(){return this.key;}
    public void setKey(String key){this.key = key;}
    public int getId(){return this.id;}
    public void setId(int id){this.id = id;}
}


//Class for storing the port numbers of each server, taken mostly from bc
//However it also includes the ports for a server that tell each process when to begin
class Ports{
	public static int KeyServerBase = 6050;
	public static int UnverifiedBlockServerPortBase = 6051;
	public static int BlockchainServerPortBase = 6052;
	public static int WaitServerBase = 6053;
   
	public static int KeyServerPort;
	public static int UnverifiedBlockServerPort;
	public static int BlockchainServerPort;
	public static int WaitServerPort;

	//Notably the ports increment by 1000 for each unique process in the group giving them unique ports
	public void setPorts(){
		KeyServerPort = KeyServerBase + (Blockchain.PID * 1000);
		UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (Blockchain.PID * 1000);
		BlockchainServerPort = BlockchainServerPortBase + (Blockchain.PID * 1000);
		WaitServerPort = WaitServerBase + (Blockchain.PID * 1000);
    }
}

//Worker class for processing incoming public keys, mostly taken from bc with notable changes
class PublicKeyWorker extends Thread {
    Socket keySock;
    PublicKeyWorker (Socket s) {keySock = s;}
    public void run(){
		//Gson variable that will be used for converting JSON data into a BlockKey
		Gson gson = new Gson();
		try{
			//Read incoming JSON data
			BufferedReader in = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
			String data = in.readLine();
			//Convert into BlockKey
			BlockKey key = gson.fromJson(data, BlockKey.class);
			//Add to global array of BlockKeys
			Blockchain.keyArray.add(key);
      }catch(IOException x){x.printStackTrace();}
    }
}

//Server class that waits for incoming public keys, taken from bc
class PublicKeyServer implements Runnable {
    public void run(){
		//initialize variables for server socket
		int q_len = 6;
		Socket keySock;
		System.out.println("Starting Public Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
		try{
			//Create server socket and wait for connection
			ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
			while (true) {
				keySock = servsock.accept();
				//Process data from connection in worker thread
				new PublicKeyWorker(keySock).start(); 
			}
		}catch(IOException e){System.out.print("Issue in PublicKeyServer");}
    }
}
  
//Worker class for processing unverified blocks, kind of taken from bc but 
//more similar to my PublicKeyWorker class
class UnverifiedBlockWorker extends Thread {
    Socket sock;
    UnverifiedBlockWorker (Socket s) {sock = s;}
    public void run(){
		//Gson variable that will be used for converting JSON data into a block
		Gson gson = new Gson();
		try{
			//Read incoming JSON data
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			String unverifiedIn = in.readLine();
			//Convert to block and add to process's queue
			BlockRecord blockRecordData = gson.fromJson(unverifiedIn, BlockRecord.class);
			Blockchain.ourPriorityQueue.add(blockRecordData);
		}catch(IOException e){System.out.print(e);}
    }
}

//Server class that waits for incoming unverified blocks, kind of taken from bc but
//more similar to my PublicKeyServer class
class UnverifiedBlockServer implements Runnable {
    public void run(){
		//initialize variables for server socket
		int q_len = 6;
		Socket sock;
		System.out.println("Starting the Unverified Block Server input thread using " +
		Integer.toString(Ports.UnverifiedBlockServerPort));
		try{
			//Create server socket and wait for connection
			ServerSocket UVBServer = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
			while (true) {
				sock = UVBServer.accept();
				//Process data from connection in worker thread
				new UnverifiedBlockWorker(sock).start(); 
			}
		}catch(IOException e){System.out.print("Issue in UnverifiedBlockServer");}
    }
  }
  
//Worker class for processing a blockchain, somewhat based off of bc with similarities to
//my other worker classes
class BlockchainWorker extends Thread {
    Socket keySock;
    BlockchainWorker (Socket s) {keySock = s;}
    public void run(){
		//Gson variable that will be used for converting JSON data into a blockchain
		Gson gson = new Gson();
		try{
			//Read incoming JSON data
			BufferedReader in = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
			String input = in.readLine();
			//Convert JSON data into an array of BlockRecords
			BlockRecord[] blockData = gson.fromJson(input, BlockRecord[].class);
			//Empty global blockchain variable
			Blockchain.recordList.clear();
			//Iterate through array and add each block to the global blockchain
			for (BlockRecord block : blockData){
				Blockchain.recordList.add(block);
			}
			//If this is process zero then run writeJSON function that will put this data in the ledger file
			if (Blockchain.PID==0)
			{
				Blockchain.writeJSON(Blockchain.recordList);
			}
		}catch(IOException x){x.printStackTrace();}
    }
  }

//Server class that waits for incoming blockchain, taken from bc
class BlockchainServer implements Runnable {
    public void run(){
		//initialize variables for server socket
		int q_len = 6;
		Socket keySock;
		try{
			//Create server socket and wait for connection
			ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
			while (true) {
				//Process data from connection in worker thread
				keySock = servsock.accept();
				new BlockchainWorker(keySock).start(); 
			}
		}catch(IOException e){System.out.print("Issue in BlockchainServer");}
    }
  }

//Worker class for processing start message, pretty much the same as the other workers but without gson
class WaitWorker extends Thread {
    Socket sock;
    WaitWorker (Socket s) {sock = s;}
    public void run(){
		try{
			//Set global start message to whatever was sent over socket
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			Blockchain.startMsg = in.readLine();
		}catch(IOException x){x.printStackTrace();}
    }
}

//Server class that waits for start message, pretty much the same as the other servers
class WaitServer implements Runnable {
	//initialize variables for server socket
    int q_len = 6;
    Socket sock;
    public void run(){
		try{
			//Create server socket and wait for connection
			ServerSocket servsock = new ServerSocket(Ports.WaitServerPort, q_len);
			while (true) {
				//Process data from connection in worker thread
				sock = servsock.accept();
				new WaitWorker(sock).start(); 
			}
		}catch(IOException e){System.out.print("Issue in WaitServer");}
    }
}

  
public class Blockchain {
    static String serverName = "localhost";
	//Number of processes, set to 3 but could be more
    static int numProcesses = 3;
	//Process ID, will be either 0, 1, or 2
    static int PID = 0;
	//Linked list of BlockRecords that makes up the global blockchain
	public static LinkedList<BlockRecord> recordList = new LinkedList<>();
	//Linked list of BlockRecords that correspond to unverified blocks in each proces
    static List<BlockRecord> blockList = new ArrayList<BlockRecord>();
	//File name of the input file processed by each process
    private static String FILENAME;
	//Comparator method taken from BlockInputG
	public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>()
    {
		@Override
		public int compare(BlockRecord b1, BlockRecord b2)
		{
			//Get timestamps of the two blocks
			String s1 = b1.getTimeStamp();
			String s2 = b2.getTimeStamp();
			//returns 0 if the timestamps are the same and -1/1 if one block is null
			if (s1 == s2) {return 0;}
			if (s1 == null) {return -1;}
			if (s2 == null) {return 1;}
			//if neither is true then run compareTo on the two blocks
			return s1.compareTo(s2);
		}
    };
	//Global queue for adding blocks to
	static Queue<BlockRecord> ourPriorityQueue = new PriorityQueue<>(4, BlockTSComparator);
	//Index of variables in the file
	private static final int iFNAME = 0;
    private static final int iLNAME = 1;
    private static final int iDOB = 2;
    private static final int iSSNUM = 3;
    private static final int iDIAG = 4;
    private static final int iTREAT = 5;
    private static final int iRX = 6;
	//String used for seed in randomAlphaNumeric function
    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	//Array for storing public keys
    public static List<BlockKey> keyArray = new ArrayList<>();
	//Private key of each process
    public static PrivateKey privateKey;
	//Start message, becomes start when process 2 indicates all process should continue
    public static String startMsg = "Wait";
	//Fake block used for begining the blockchain
    public static LinkedList<BlockRecord> dummyBlock(){
		//will be return value that starts the blockchain in each process
        LinkedList<BlockRecord> startBlockChain = new LinkedList<>();
		//Fake block of made up data unrelated to inputs
        BlockRecord fakeBlock = new BlockRecord();
        String suuid = new String(UUID.randomUUID().toString());
        fakeBlock.setBlockID(suuid);
        try{Thread.sleep(1000);}catch(InterruptedException e){}
        Date date = new Date();
        String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
        String TimeStampString = T1 + "." + Blockchain.PID; 
		//Fill fake block with data
        fakeBlock.setTimeStamp(TimeStampString); 
        fakeBlock.setVerificationProcessID("0");
        fakeBlock.setPreviousHash("0000000000000000000000000000000000000000000000000000000000000000");
        fakeBlock.setFname("Fake");
		fakeBlock.setLname("Block");
		fakeBlock.setDOB("00-00-0000");
        fakeBlock.setSSNum("111-11-1111");
		fakeBlock.setDiag("Not enough blocks"); 
        fakeBlock.setRx("Blocks");
        fakeBlock.setTreat("More blocks");
        fakeBlock.setRandomSeed("00AA11BB");
		fakeBlock.setIndex(0);
		//The following is mostly taken from BlockJ
		//Concatenated string of fake block's data
        String blockData =
            fakeBlock.getTimeStamp() +
            fakeBlock.getBlockID() +
            fakeBlock.getPreviousHash() + 
            fakeBlock.getFname() +
            fakeBlock.getLname() +
            fakeBlock.getDOB() +
            fakeBlock.getSSNum() +
            fakeBlock.getVerificationProcessID() +
            fakeBlock.getDiag() +
            fakeBlock.getTreat() +
            fakeBlock.getRx() +
			fakeBlock.getRandomSeed() +
			fakeBlock.getIndex() +
			fakeBlock.getSignedID();
		String SHA256String = "";
		try{
			//make the SHA-256 Hash Digest of the block
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update (blockData.getBytes());
			byte byteData[] = md.digest();
		
			//Convert hashed bytes into hex
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < byteData.length; i++) {
				sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
			}
			SHA256String = sb.toString();
		}catch(NoSuchAlgorithmException x){};
		String temp = SHA256String.toUpperCase();
        fakeBlock.setWinningHash(temp);
		//Add fake block to the blockchain
        startBlockChain.add(fakeBlock);
        return startBlockChain;
    }
	
	//Taken directly from BlockJ, generates the key pair for signing
    public static KeyPair generateKeyPair(long seed) throws Exception {
		//Create keygen that uses RSA and randomgen with SHA1PRNG
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
		//Use seed provided for randomization
        rng.setSeed(seed);
		//Generate key pair of size 1024
        keyGenerator.initialize(1024, rng);
        return (keyGenerator.generateKeyPair());
    }
	
	//Taken directly from BlockJ, signs data with private key
    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
		//Create signer with SHA1withRSA
        Signature signer = Signature.getInstance("SHA1withRSA");
		//Sign with private key
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }

	//Taken directly from BlockJ, verifies the signature
    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
		//Create signer with SHA1withRSA
        Signature signer = Signature.getInstance("SHA1withRSA");
		//Check if signature was signed with the right private key
        signer.initVerify(key);
        signer.update(data);
        return (signer.verify(sig));
    }
	
	//Function used to send public key to each process
    public void keySend(BlockKey key) throws Exception {
        Socket sock;
        PrintStream toServer;
		//Convert key into JSON
        Gson gson = new GsonBuilder().create();
        String keyData = gson.toJson(key);
        try{
			//Send to each process, taken from bc
			for(int i=0; i< numProcesses; i++){
				sock = new Socket(serverName, Ports.KeyServerBase + (i * 1000));
				toServer = new PrintStream(sock.getOutputStream());
            toServer.println(keyData); toServer.flush();
        } 
        }catch (Exception x) {x.printStackTrace ();}
    }
	
	//Function used to send start message to each process
    public void waitSend() throws Exception {
		Socket sock;
		PrintStream toServer;
		try{
		//Send Start to each process, taken from bc
			for(int i=0; i< numProcesses; i++){
				sock = new Socket(serverName, Ports.WaitServerBase + (i * 1000));
				toServer = new PrintStream(sock.getOutputStream());
				toServer.println("Start"); toServer.flush();
			} 
		}catch (Exception x) {x.printStackTrace ();}
    }
	
	//Function used to send unverified blocks to each process
    public void unverifiedSend(BlockRecord block, int ServerBase) throws Exception {
        Socket UVBsock;
        PrintStream toServer;

		//Convert block into JSON
		Gson gson = new GsonBuilder().create();
        String blockData = gson.toJson(block);
		
        try{
			//Send Start to each process, taken from bc
			for(int i=0; i< numProcesses; i++){
				UVBsock = new Socket(serverName, ServerBase + (i * 1000));
				toServer = new PrintStream(UVBsock.getOutputStream());
				toServer.println(blockData); toServer.flush();
			}
        }catch (Exception x) {x.printStackTrace ();}
    }
	
	//Function used to send blockchain to each process
    public void blockChainSend(LinkedList<BlockRecord> blockChainRecord, int ServerBase) throws Exception {
		Socket sock;
		PrintStream toServer;

		Gson gson = new GsonBuilder().create();
		String recordData = "[";
		try{
			//Iterate through each block and convert data to JSON then seperate with comma, except for last one
			for (BlockRecord block: blockChainRecord){
				recordData += gson.toJson(block);
				if (blockChainRecord.indexOf(block) != blockChainRecord.size() - 1)
					recordData += ",";
			}
			recordData = recordData + "]";
			
			//Send blockchain to each process, taken from bc
			for(int i=0; i< numProcesses; i++){
				sock = new Socket(serverName, ServerBase + (i * 1000));
				toServer = new PrintStream(sock.getOutputStream());
				toServer.println(recordData); toServer.flush();
			} 
		}catch (Exception x) {x.printStackTrace ();}
    }
    
	//Taken directly from WorkB, creates a random string of a certain length
    public static String randomAlphaNumeric(int count) {
        StringBuilder builder = new StringBuilder();
		//Build string until limit is reached, which is set by count
        while (count-- != 0) {
			int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
			builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }
	
	//Work method used to simulate work in a blockchain. 
    public static BlockRecord blockWork(BlockRecord block){
        //Will contain random seed plus block data
		String concatString = "";
		//Will contrain the new SHA256 string in hex
        String stringOut = "";
		//Use previous winning hash to start
        block.setPreviousHash(Blockchain.recordList.get(0).getWinningHash());
		//Set the corresponding verification PID and index
        block.setVerificationProcessID(Integer.toString(Blockchain.PID));
		block.setIndex(Blockchain.recordList.get(0).getIndex() + 1);
		//Concatenate the blocks variables into a string
		String blockData = 
            block.getTimeStamp() +
            block.getBlockID() +
            block.getPreviousHash() + 
            block.getFname() +
            block.getLname() +
            block.getDOB() +
            block.getSSNum() +
            block.getVerificationProcessID() +
            block.getDiag() +
            block.getTreat() +
            block.getRx() +
			block.getIndex() +
			block.getSignedID();
		//Initialize these variables for use in the while loop
		String randString;
		int workNumber;
        try {
			//Run forever until block is verified or abandoned
            while (true) { 
				//Create a random string of length 8 and concatenate it with the block variables
                randString = randomAlphaNumeric(8); 
                concatString = blockData + randString;
				//Hash the combined string into bytes and convert to hex, the majority of this code is taken from WorkB
                MessageDigest MD = MessageDigest.getInstance("SHA-256");
                byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8")); 
                stringOut = DatatypeConverter.printHexBinary(bytesHash); //I am in java 1.8 so I use this
                System.out.println("Hash is: " + stringOut);
				//Take the first 4 hex values, convert to decimal and then see if its lower then 20000
                workNumber = Integer.parseInt(stringOut.substring(0,4),16); 
                System.out.println("First 16 bits in Hex and Decimal: " + stringOut.substring(0,4) +" and " + workNumber);
                if (!(workNumber < 20000)){ 
                    System.out.format("%d is not less than 20,000 so we did not solve the puzzle\n\n", workNumber);
                }
                if (workNumber < 20000){
                    System.out.format("%d IS less than 20,000 so puzzle solved!\n", workNumber);
					System.out.println("The seed (puzzle answer) was: " + randString);
					//Set the seed and winning hash to the corrresponding values
                    block.setRandomSeed(randString);
                    block.setWinningHash(stringOut);
					//Sign with private key
                    byte[] signedWinByte = signData(bytesHash, privateKey);
                    String signedWinString = Base64.getEncoder().encodeToString(signedWinByte);
                    block.setSignedWinningHash(signedWinString);
                    break;
                }
				//See if block has already been added and if so abandon
                for (BlockRecord temp: recordList){
                  if (temp.getBlockID().equals(block.getBlockID())){
                    System.out.println("Abandoning verification");
                    BlockRecord finishedBlock = new BlockRecord();
                    finishedBlock.setBlockID("Aborted");
                    return finishedBlock;
                  }
                }
				try{Thread.sleep(10000);}catch(InterruptedException e){}
            }
        }catch(Exception ex) {ex.printStackTrace();}

        return block;
    }
	//Used to write blockchain into JSON, some code taken from BlockJ
    public static void writeJSON(LinkedList<BlockRecord> blockchainRecord){
        Gson gsonPretty = new GsonBuilder().setPrettyPrinting().create();

        String blockchainJSON = "[";
		//Iterate through each block in blockchain and write in JSON, if not last block add comma
        for (BlockRecord block: blockchainRecord){
			blockchainJSON += gsonPretty.toJson(block);
			if (blockchainRecord.indexOf(block) != blockchainRecord.size() - 1){
				blockchainJSON += ",";
			}
        }
        blockchainJSON += "]";

		//Write the blockchain into a ledger
        try (FileWriter writer = new FileWriter("BlockchainLedger.json", false)) {
          writer.write(blockchainJSON);
        } catch (IOException e) {
          e.printStackTrace();
        }
    }
    
    public static void main(String args[]) throws Exception {
        int q_len = 6;
        //Make sure PID is 0, 1, or 2
		if (Integer.parseInt(args[0]) > 2)
		{
			System.out.println("You must use 0, 1, or 2");
            throw new IllegalArgumentException();
		}
        else
		{
            PID = Integer.parseInt(args[0]);
        }
		
        System.out.println("Welcome to my Blockchain program. Press Ctrl-c to quit\n");
        System.out.println("Your processID is " + PID + "\n");
        
		//Initialize for each process
        new Ports().setPorts(); 
		
		//Create a key pair for this process using a random seed
		Random random = new Random();
        long randomSeed = random.nextInt(1000);
        KeyPair keyPair = generateKeyPair(randomSeed);
        privateKey = keyPair.getPrivate();
		//Get byte form of public key and convert it to string form for sending
        byte[] byteSignature = keyPair.getPublic().getEncoded();
        String stringSignature = Base64.getEncoder().encodeToString(byteSignature);
        System.out.println("String Sig = " + stringSignature);
        BlockKey key = new BlockKey();
        key.setKey(stringSignature);
		key.setId(PID);

		//Create listener threads
        new Thread(new WaitServer()).start();
        new Thread(new PublicKeyServer()).start();
        new Thread(new UnverifiedBlockServer()).start();
        new Thread(new BlockchainServer()).start();
		
        System.out.println("Waiting");
		//Wait, unless this is process 2 and if so send start message to each process
        if (PID==2)
		{
			new Blockchain().waitSend();
			System.out.println("Starting from Process 2");
        }
        try{Thread.sleep(5000);}catch(Exception e){}
        if (startMsg.equals("Start"))
		{
			//Send each process the public keys and create the blockchain
			new Blockchain().keySend(key);
			try{Thread.sleep(10000);}catch(Exception e){}
			recordList = dummyBlock();
			
			//Set the input file for each process then create list of blocks taken from BlockInputG
			List<BlockRecord> inputList = new ArrayList<>();
			switch(PID){
				case 1: FILENAME = "BlockInput1.txt"; break;
				case 2: FILENAME = "BlockInput2.txt"; break;
				default: FILENAME= "BlockInput0.txt"; break;
			}
			System.out.println("Using input file: " + FILENAME);
			try {
				BufferedReader br = new BufferedReader(new FileReader(FILENAME));
				String[] tokens = new String[10];
				String InputLineStr;
				String suuid;
				UUID idA;
				BlockRecord tempRec;
				StringWriter sw = new StringWriter();
				int n = 0;
				//Read each block
				while ((InputLineStr = br.readLine()) != null) {
					BlockRecord BR = new BlockRecord(); 
					try{Thread.sleep(1001);}catch(InterruptedException e){}
					Date date = new Date();
					String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
					String TimeStampString = T1 + "." + PID; 
					BR.setTimeStamp(TimeStampString); 
					//Set the values of each block
					suuid = new String(UUID.randomUUID().toString());
					BR.setBlockID(suuid);
					byte[] digitalSignature = signData(suuid.getBytes(), privateKey);
					String SignedSHA256ID = Base64.getEncoder().encodeToString(digitalSignature);
					BR.setSignedID(SignedSHA256ID);
					tokens = InputLineStr.split(" +"); 
					BR.setFname(tokens[iFNAME]);
					BR.setLname(tokens[iLNAME]);
					BR.setSSNum(tokens[iSSNUM]);
					BR.setDOB(tokens[iDOB]);
					BR.setDiag(tokens[iDIAG]);
					BR.setTreat(tokens[iTREAT]);
					BR.setRx(tokens[iRX]);
					BR.setVerificationProcessID(Integer.toString(Blockchain.PID));
					BR.setIndex(n);
					inputList.add(BR);
					n++;
				}
			} catch (Exception e){System.out.println(e);}
			
			blockList = inputList;
		}
		
        for (BlockRecord block: blockList){
            new Blockchain().unverifiedSend(block, Ports.UnverifiedBlockServerPortBase);
		}
        System.out.println("Unverified blocks sent");

        try{Thread.sleep(5000);}catch(Exception e){}
        //Run forever until blockchain is fully verified
        while (true){
              try{Thread.sleep(2000);}catch(InterruptedException e){}
              System.out.println(ourPriorityQueue.size() + " blocks are left");
              BlockRecord tempRec = ourPriorityQueue.poll();
              if (tempRec == null) break;
			  System.out.println(tempRec.getTimeStamp() + " " + tempRec.getFname() + " " + tempRec.getLname());
			  //Check which process made this block
              String stringKey = "";
              for (BlockKey tempKey: keyArray){
                if (Integer.toString(tempKey.getId()).equals(tempRec.getVerificationProcessID())){
                  stringKey = tempKey.getKey();
                  System.out.println("Using the key " + tempKey.getId());
                }
              }
			  //Convert public key and signature into bytes then verify the signature, taken from BlockJ
              byte[] bytePubKey = Base64.getDecoder().decode(stringKey);
              byte[] testSignature = Base64.getDecoder().decode(tempRec.getSignedID());
              X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(bytePubKey);
              KeyFactory keyFactory = KeyFactory.getInstance("RSA");
              PublicKey RestoredKey = keyFactory.generatePublic(pubSpec);
              boolean verified = verifySig(tempRec.getBlockID().getBytes(), RestoredKey, testSignature);
			  boolean inBlockchain = false;
			  //If the block is verified continue
			  if(!verified){
                System.out.println("Block not verified");
              }
              else {
                try{Thread.sleep(1000);}catch(InterruptedException e){}
				//Iterate through blockchain to see if the block is already in the blockchain
                for (BlockRecord check: recordList){
					if (check.getBlockID().equals(tempRec.getBlockID())){
						inBlockchain = true;
						System.out.println("Block already added to blockchain");
					}
                }
                BlockRecord currentBlock = new BlockRecord();
				//If the block is not already in the blockchain then verify it
                while (!inBlockchain){
					System.out.println("Verifying block");
					currentBlock = blockWork(tempRec);
					//Check the winning hash of the first block to see if the block is modified
					String headHash = recordList.get(0).getWinningHash();
					if (!currentBlock.getBlockID().equals("Aborted")){
						if (currentBlock.getPreviousHash().equals(headHash)){
							//Since it is unmodified add it to blockchain
							recordList.addFirst(currentBlock);
							new Blockchain().blockChainSend(recordList, Ports.BlockchainServerPortBase);
							inBlockchain = true;
							System.out.println("Block added to blockchain");
						}
						else {
							//Check if it is already in the blockchain
							for (BlockRecord check: recordList){
								if (check.getBlockID().equals(currentBlock.getBlockID())){
									inBlockchain = true;
								}
							}
						}
					}
					//If aborted then try next block in queue
					else break;
				}
            }
        }
		//Program is finished so move to console commands
        System.out.println("The Blockchain has been computed");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in)); 
		String input;
		while(true) {
			System.out.print("Type in 'list' for a list of the blockchain, type in 'credit' for a list of credits");
			System.out.println("");
			System.out.flush();
			input = in.readLine();
			if (input.equals("list"))
			{
				//List the data of the blocks in the blockchain
				for (BlockRecord temp: recordList)
				{
					String list = "Timestamp = "
					+ temp.getTimeStamp() + ", First Name = "
					+ temp.getFname() + ", Last Name = "
					+ temp.getLname() + ", SSN = "
					+ temp.getSSNum() + ", DOB = "
					+ temp.getDOB() + ", Diag = "
					+ temp.getDiag() + ", Treatment = "
					+ temp.getTreat() + ", Rx = "
					+ temp.getRx() + ", Index = "
					+ temp.getIndex();
					System.out.println(list);
				}
			}
			else if (input.equals("credit")) 
			{
				//List how many blocks each process verified
				int count1 = 0;
				int count2 = 0;
				int count3 = 0;
				for (BlockRecord temp: recordList)
				{
					if (Integer.parseInt(temp.getVerificationProcessID()) == 0)
						count1++;
					else if (Integer.parseInt(temp.getVerificationProcessID()) == 1)
						count2++;
					else if (Integer.parseInt(temp.getVerificationProcessID()) == 2)
						count3++;
				}
				System.out.println("Process 0 = "+count1+" Process 1 = "+count2+" Process 2 = "+count3);
			}
		}
    }
}

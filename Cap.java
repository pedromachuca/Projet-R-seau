/*  Pierre Coiffey
	wireshark like v1
	07/11/2018
											
	How to launch :
	Java 11 2018-09-25
	Java(TM) SE Runtime Environment 18.9 (build 11+28)
	Java HotSpot(TM) 64-Bit Server VM 18.9 (build 11+28, mixed mode)

	This program allows you to display the informations contained in
	a pcap file as wireshark would. The program is limited i.e. not 
	all protocols can be printed. The following protocols can be displayed :
	
	-Ethernet
	-ARP
	-ICMP
	-IP
	TO DO: 
	(TCP, UDP, DNS, DHCP, HTTP, FTP) 
	Fragmentation IP
	
	You will see later (section Arguments) that you will have to specify the pcap
	file you wish to display. In addition you can specify a particular protocol
	to display only the packet information's for this protocol. Or leave it with
	no arguments. By default the program will display all protocols.

	To start the program please compile this code 
	with the following command line.
	
	javac Cap.java
													
	Then to launch the program enter the following command line :
													  
	java Cap [argument0] [argument1]
	
	Arguments:

	argument0 : pcap file 
	argument1 : protocol you wish to display 
				leave it empty if you want to
				display all protocols
*/
import java.io.*;
import java.net.*;

class Ethernet{

	public int PrintEth(byte[] data){
		System.out.print("Ethernet    ");
		System.out.print("Mac DST              ");
		System.out.println("Mac SRC  ");
		System.out.print("            ");
		for(int i=0; i<6; i++){
			System.out.format("%02X ", data[i]);	
		}
		System.out.print("   ");
		for(int i=6; i<12; i++){
			System.out.format("%02X ", data[i]);	
		}
		byte data1 = 0x0000;
		for(int i=12; i<14;i++){
			 data1+= data[i];
		}
		switch (data1){
			case 14:
				return 14;
			case 8:
				return 8;
			default: 
				System.out.println("Default");
				break;
		}
		return 0;
	}
}
class Arp{
	public void PrintArp(byte[] data){
		System.out.print("\nARP ");
		if(data[7]== 1){
			System.out.print("Request ");
		}
		else{
			System.out.print("Reply   ");	
		}
		System.out.print("IP SRC       ");
		System.out.print("MAC SRC               ");
		System.out.print("IP DST       ");	
		System.out.println("MAC DST       ");	
		System.out.print("            ");
		for(int i=14; i<18; i++){
			System.out.format("%d ", data[i]&255);	
		}
		System.out.print("   ");
		for(int i=8; i<14; i++){		
			System.out.format("%02X ",data[i]);	
		}
		System.out.print("   ");
		for(int i=24; i<28; i++){
			System.out.format("%d ", data[i]&255);	
		}
		System.out.print("   ");
		for(int i=18; i<24; i++){		
			System.out.format("%02X ",data[i]);	
		}
		
	}
}
class Ip{
	public int PrintIp(byte[] data){
		System.out.print("\nIp\n");
		System.out.print("TTL    ");
		System.out.print("IP SRC        ");
		System.out.println("IP DST       ");	
		System.out.format("%d    ", data[8]&255);
		for(int i=12; i<16; i++){
			System.out.format("%d ", data[i]&255);	
		}
		System.out.print("   ");
		for(int i=16; i<20; i++){		
			System.out.format("%d ",data[i]&255);	
		}	
		System.out.print("\nProtocol :");
		if(data[9]== 1){
			System.out.print("ICMP    ");
		}
		else if(data[9]==6){
			System.out.print("TCP   ");	
			return 1;
		}
		else if(data[9]==17){
			System.out.print("UDP   ");	
			return 2;
		}
		return 0;
	}
	/*public byte[] ReassemblyIp(byte [] data){
		String s =Integer.toBinaryString(data[6] & 0xFF);
		String s1 =Integer.toBinaryString(data[7] & 0xFF);
		System.out.print("data[6] : "+s+"data[7]"+s1);	
		//System.out.print("\ntest reassembly :");	
		//System.out.format("%02X ",data[6]);	
		//System.out.format("%02X ",data[7]);	
		
		return data;
	}*/
}
class Layer4{
	public void PrintTcp(byte [] data){
		int srcPort= (data[20]<< 8)&0xff00|data[21]&0x00ff;
		int dstPort= (data[22]<< 8)&0xff00|data[23]&0x00ff;
		System.out.println("Src port :"+srcPort+"  Dst port :"+dstPort);
		long sequenceNumber=((long)data[24]&0xFF)<<24|((long)data[25]&0xFF)<<16|((long)data[26]&0xFF)<<8|((long)data[27]&0xFF);
		long ackNumber=((long)data[28]&0xFF)<<24|((long)data[29]&0xFF)<<16|((long)data[30]&0xFF)<<8|((long)data[31]&0xFF);

		System.out.println("\nsequence Number:"+sequenceNumber);
		System.out.println("acknowlegment Number:"+ackNumber);

		//Format de data[32] :1234 5678
		//1234 -> header length sur 4 bit
		//567 -> Reserved sur 3 bit
		//8 -> Nonce sur 1 bit
		int headerLength= (data[32]>>4)&0x0f;
		System.out.println("header length:"+(headerLength*4)+"bytes");
		//Format de data[33]: 1234 5678
		//1 -> Congestion Window Reduced
		//2 -> ECN-ECHO
		//3 -> Urgent
		//4 -> Acknowledgment !!
		int ack = (data[33]>>4)&0x01;
		System.out.println("ack : "+ack);
		//5 ->Push
		//6 ->Reset
		//7 ->Syn
		int syn= (data[33]>>1)&0x01;
		System.out.println("syn : "+syn);
		//8 ->Fin
		int fin= data[33]&0x01;
		System.out.println("fin : "+fin);

		//Format data[33], data[34]: 2 octet -> window size value
		//Format data[35], data[36]: checksum 
		//Then Options on 20 bytes, Max segment size, SACK permitted, Timestamps, No-Operation(NOP), window scale		
	}
	public void PrintUdp(byte [] data){
		int srcPort= (data[20]<< 8)&0xff00|data[21]&0x00ff;
		int dstPort= (data[22]<< 8)&0xff00|data[23]&0x00ff;
		System.out.println("Src port :"+srcPort+"  Dst port :"+dstPort);
		int Length= (data[24]<< 8)&0xff00|data[25]&0x00ff;
		System.out.println("Length :"+Length);
		System.out.print("Checksum :");
		System.out.format("%02X %02X\n", data[26], data[27]);
			
	}
}
class Packet{
	public int Plength(byte [] data){
		byte length = data[8];
		//Find a method to take the octet 8 and 9 the length 
		//should be data[9]data[8] (inverted) and converted to an 
		//int verify the position of the fragementation  F203
		//donne 61955 and 03F2 ->1010
		int i= (data[9]<< 8)&0xff00|data[8]&0x00ff;
		return i;
	}
}

class Cap{

	public static void main(String[] args) {

		if (args.length < 1) {
			System.out.println("No file were specified.\nPlease enter the following command line :\njava Cap file.pcap -option");
			System.exit(1);
		}

		try{
			File cap = new File(args[0]);
			FileInputStream inputstream = new FileInputStream(cap);
			long fileLength = cap.length();
			byte[] filecontent = new byte[(int)fileLength];
			int data = inputstream.read(filecontent);
			while(data != -1){
				data = inputstream.read(filecontent);
			}
			//for(int i=0; i<filecontent.length; i++){
			//	System.out.format("%02X ", filecontent[i]);	
			//}
			int startC =24;
			int packetNumber = 1;
			byte [] MagicNum = new byte[4];
			for(int i=0; i<4; i++){
				MagicNum[i] = filecontent[i];	
			}
			StringBuilder sb = new StringBuilder(8);
			for(byte b: MagicNum){
				sb.append(String.format("%02x", b));
			}
			StringBuilder b= new StringBuilder("d4c3b2a1");
			if (sb.toString().equals(b.toString())){
				 System.out.println( "\nThe file is a pcap format ! Starting execution ..." );
			}
			else{
				 System.out.println( "The file is not a pcap format ! Exiting program" );
				 System.exit( 1 );
			}
			while(true){
				System.out.format("\n--------------Packet %d ------------------------------------------------------------", packetNumber);		
				int packetHSize = 16;
				byte[] FirstPh= new byte[packetHSize];
				int endPH = startC + packetHSize;
				for(int i=startC; i<endPH; i++){
					FirstPh[i-startC]=filecontent[i];
				}
			
				System.out.println("\n");	
				inputstream.close();
			
				Packet packetheader = new Packet();
				int packetLength = packetheader.Plength(FirstPh);		

				byte[] FirstPacket= new byte[packetLength];
				for(int i=endPH; i<packetLength+endPH; i++){
					FirstPacket[i-endPH]=filecontent[i];
				}
				int ethSize = 14;
				int endEth = endPH+ethSize;
				byte[] EthPacket= new byte[ethSize];
				for(int i=endPH; i<endEth; i++){
					EthPacket[i-endPH]=filecontent[i];
				}
				Ethernet packetEthernet = new Ethernet();
				int type = packetEthernet.PrintEth(EthPacket);
				int endPacket = endPH+packetLength;
				if(type==14){
					byte[] packet= new byte[endPacket];
	 				for(int i=endEth; i<endPacket; i++){
		 				packet[i-endEth]=filecontent[i];
					}
					Arp packetArp = new Arp();
					packetArp.PrintArp(packet);
				}
				else if(type==8){
					byte[] packet= new byte[endPacket];
	 				for(int i=endEth; i<endPacket; i++){
		 				packet[i-endEth]=filecontent[i];
					}
					Ip packetIp = new Ip();
					int protocol =packetIp.PrintIp(packet);
					//packetIp.ReassemblyIp(packet);
					if(protocol !=0){
						Layer4 layer4 = new Layer4();
						if(protocol==1){
							layer4.PrintTcp(packet);
						}
						else if(protocol==2){
							layer4.PrintUdp(packet);
						}
					}
				}
				startC=endPacket;
				if(endPacket==fileLength){
					System.out.println("\nEnd of while");
					break;
				}
				packetNumber++;
			System.out.format("\n\npacket length : %d\n\n", packetLength);
			}
		}catch (IOException ex) {
			System.out.format("IO Exception");
		}

	}
}


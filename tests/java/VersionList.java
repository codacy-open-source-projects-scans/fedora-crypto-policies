import java.net.URL;
import java.io.*;
import javax.net.ssl.*;
 
public class VersionList
{
  public static void main(String[] args)
  throws Exception
  {
    SSLContext context = SSLContext.getDefault();
    int i;
    SSLSocketFactory sf = context.getSocketFactory();
    SSLSocket skt = (SSLSocket)sf.createSocket();
    String[] protocols = skt.getEnabledProtocols();

    System.out.println("Protocols:");
    for (i=0;i<protocols.length;i++)
    {
      System.out.println(protocols[i]);
    }

    System.exit(0);
  }
}


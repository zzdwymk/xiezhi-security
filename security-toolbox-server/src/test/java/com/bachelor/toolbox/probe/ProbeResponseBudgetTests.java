package com.bachelor.toolbox.probe;
import static org.assertj.core.api.Assertions.*;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.io.IOException;
import org.junit.jupiter.api.Test;
class ProbeResponseBudgetTests {
 @Test void oversizePageIsRejectedDuringResponseReception() throws Exception {
  HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
  server.createContext("/large",e->{byte[] data=new byte[2*1024*1024+1];try{e.sendResponseHeaders(200,0);e.getResponseBody().write(data);}catch(IOException ignored){}finally{e.close();}});server.start();
  try{var service=new ProbeService(null,null,null,null,null,null,null);var send=ProbeService.class.getDeclaredMethod("send",URI.class);send.setAccessible(true);
   assertThatThrownBy(()->send.invoke(service,URI.create("http://127.0.0.1:"+server.getAddress().getPort()+"/large"))).hasCauseInstanceOf(IOException.class);
  }finally{server.stop(0);}
 }
}

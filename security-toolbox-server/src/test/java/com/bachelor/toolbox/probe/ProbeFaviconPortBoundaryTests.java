package com.bachelor.toolbox.probe;
import static org.assertj.core.api.Assertions.assertThat;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
class ProbeFaviconPortBoundaryTests {
 @Test void sameOriginRelativeIconRemainsFetchable() throws Exception {
  HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);var hits=new AtomicInteger();
  server.createContext("/icon",exchange->{hits.incrementAndGet();exchange.sendResponseHeaders(200,1);exchange.getResponseBody().write(1);exchange.close();});server.start();
  try {
   var service=new ProbeService(null,null,null,null,null,null,null);
   var method=ProbeService.class.getDeclaredMethod("fetchFavicon",String.class,String.class);method.setAccessible(true);
   method.invoke(service,"http://127.0.0.1:"+server.getAddress().getPort()+"/page","<link rel='icon' href='/icon'>");
   assertThat(hits.get()).isEqualTo(1);
  } finally {server.stop(0);}
 }
 @Test void sameHostDifferentPortIconCannotTriggerRequest() throws Exception {
  HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);var hits=new AtomicInteger();
  server.createContext("/icon",exchange->{hits.incrementAndGet();exchange.sendResponseHeaders(200,1);exchange.getResponseBody().write(1);exchange.close();});server.start();
  try {
   int foreignPort=server.getAddress().getPort();int pagePort=foreignPort==18000?18001:18000;
   var service=new ProbeService(null,null,null,null,null,null,null);
   var method=ProbeService.class.getDeclaredMethod("fetchFavicon",String.class,String.class);method.setAccessible(true);
   method.invoke(service,"http://127.0.0.1:"+pagePort+"/page","<link rel='icon' href='http://127.0.0.1:"+foreignPort+"/icon'>");
   assertThat(hits.get()).isZero();
  } finally {server.stop(0);}
 }
}

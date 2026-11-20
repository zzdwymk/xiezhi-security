package com.bachelor.toolbox.fingerprint;
import static org.assertj.core.api.Assertions.assertThat;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
class FaviconHashContractTests {
 @Test void murmur3MatchesPublishedAsciiVectorsAndOffsetSlice(){
  byte[] foo="foo".getBytes(StandardCharsets.US_ASCII),hello="hello".getBytes(StandardCharsets.US_ASCII);
  assertThat(FaviconHashUtil.murmur3_32(foo,0,3,0)).isEqualTo(-156908512);
  assertThat(FaviconHashUtil.murmur3_32(hello,0,5,0)).isEqualTo(613153351);
  byte[] padded="xxfooyy".getBytes(StandardCharsets.US_ASCII);
  assertThat(FaviconHashUtil.murmur3_32(padded,2,3,0)).isEqualTo(-156908512);
 }
 @Test void emptyAndMd5ContractsRemainDeterministic(){
  assertThat(FaviconHashUtil.calculateMurmur3(null)).isEmpty();
  assertThat(FaviconHashUtil.calculateMd5(new byte[0])).isEmpty();
  assertThat(FaviconHashUtil.calculateMd5("abc".getBytes(StandardCharsets.US_ASCII))).isEqualTo("900150983cd24fb0d6963f7d28e17f72");
 }
}

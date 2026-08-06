package com.bachelor.toolbox.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FingerprintRuleCatalogTests {
  @TempDir Path tempDirectory;

  @Test
  void hidesParserDetailsWhenExternalCatalogIsMalformed() throws Exception {
    Path rulesFile = tempDirectory.resolve("rules.json");
    Files.writeString(rulesFile, "internal-secret-token");
    FingerprintRuleCatalog catalog =
        new FingerprintRuleCatalog(new ObjectMapper(), rulesFile.toString());

    assertThatThrownBy(catalog::reload)
        .isInstanceOf(ApiException.class)
        .hasMessage("无法加载指纹规则，请检查规则文件后重试")
        .hasMessageNotContaining("internal-secret-token")
        .hasMessageNotContaining("JsonParseException")
        .hasMessageNotContaining(rulesFile.toString());
  }

  @Test
  void reportsCatalogValidationFailureInChinese() throws Exception {
    Path rulesFile = tempDirectory.resolve("missing-version.json");
    Files.writeString(rulesFile, "{\"version\":\"\",\"rules\":[]}");
    FingerprintRuleCatalog catalog =
        new FingerprintRuleCatalog(new ObjectMapper(), rulesFile.toString());

    assertThatThrownBy(catalog::reload)
        .isInstanceOf(ApiException.class)
        .hasMessage("指纹规则缺少版本号或规则列表")
        .hasMessageNotContaining("version")
        .hasMessageNotContaining("rules");
  }

  @Test
  void loadsRulesInOrderAndAcceptsConfidenceBoundaries() throws Exception {
    String json =
        """
        {
          "version": "v1",
          "rules": [
            {
              "id": "minimum",
              "name": "Minimum",
              "category": "TEST",
              "confidence": 1,
              "body": ["first"]
            },
            {
              "id": "maximum",
              "name": "Maximum",
              "category": "TEST",
              "confidence": 100,
              "title": ["second"]
            }
          ]
        }
        """;
    Path rulesFile = tempDirectory.resolve("valid-rules.json");
    Files.writeString(rulesFile, json);
    FingerprintRuleCatalog catalog =
        new FingerprintRuleCatalog(new ObjectMapper(), rulesFile.toString());

    FingerprintRuleCatalog.CatalogInfo info = catalog.reload();

    assertThat(info.version()).isEqualTo("v1");
    assertThat(info.ruleCount()).isEqualTo(2);
    assertThat(info.sha256()).isEqualTo(sha256(json));
    assertThat(catalog.rules())
        .extracting(FingerprintRuleCatalog.Rule::id)
        .containsExactly("minimum", "maximum");
    assertThat(catalog.rules())
        .extracting(FingerprintRuleCatalog.Rule::confidence)
        .containsExactly(1, 100);
  }

  @Test
  void rejectsConfidenceOutsideTheSupportedRangeInChinese() throws Exception {
    Path rulesFile = tempDirectory.resolve("invalid-confidence.json");
    Files.writeString(
        rulesFile,
        """
        {
          "version": "v1",
          "rules": [{"id":"invalid","name":"Invalid","confidence":0}]
        }
        """);
    FingerprintRuleCatalog catalog =
        new FingerprintRuleCatalog(new ObjectMapper(), rulesFile.toString());

    assertThatThrownBy(catalog::reload).isInstanceOf(ApiException.class).hasMessage("指纹规则名称或置信度无效");
  }

  @Test
  void keepsThePreviousCatalogWhenReloadFails() throws Exception {
    Path rulesFile = tempDirectory.resolve("reload-rules.json");
    Files.writeString(
        rulesFile,
        """
        {
          "version": "stable",
          "rules": [{"id":"stable","name":"Stable","confidence":80}]
        }
        """);
    FingerprintRuleCatalog catalog =
        new FingerprintRuleCatalog(new ObjectMapper(), rulesFile.toString());
    FingerprintRuleCatalog.CatalogInfo previousInfo = catalog.reload();

    Files.writeString(rulesFile, "internal-secret-token");

    assertThatThrownBy(catalog::reload)
        .isInstanceOf(ApiException.class)
        .hasMessage("无法加载指纹规则，请检查规则文件后重试");
    assertThat(catalog.info()).isEqualTo(previousInfo);
    assertThat(catalog.rules())
        .extracting(FingerprintRuleCatalog.Rule::id)
        .containsExactly("stable");
  }

  private String sha256(String value) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes());
    return HexFormat.of().formatHex(digest);
  }
}

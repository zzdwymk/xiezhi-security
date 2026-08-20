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
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

@ExtendWith(OutputCaptureExtension.class)
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

  @Test
  void updatesConfiguredCatalogAtomicallyAndReloadsItAfterRestart() throws Exception {
    String initial =
        """
        {"version":"old","rules":[{"id":"old","name":"Old","confidence":70}]}
        """;
    String updated =
        """
        {"version":"new","rules":[{"id":"new","name":"New","confidence":90}]}
        """;
    Path rulesFile = tempDirectory.resolve("external-rules.json");
    Files.writeString(rulesFile, initial);
    FingerprintRuleCatalog catalog =
        new FingerprintRuleCatalog(new ObjectMapper(), rulesFile.toString());
    catalog.reload();

    FingerprintRuleCatalog.CatalogInfo info = catalog.update(updated.getBytes());

    assertThat(info.version()).isEqualTo("new");
    assertThat(info.ruleCount()).isEqualTo(1);
    assertThat(info.source()).isEqualTo(FingerprintRuleCatalog.CatalogSource.EXTERNAL);
    assertThat(info.sha256()).isEqualTo(sha256(updated));
    assertThat(Files.readString(rulesFile)).isEqualTo(updated);
    assertThat(catalog.rules()).extracting(FingerprintRuleCatalog.Rule::id).containsExactly("new");

    FingerprintRuleCatalog restarted =
        new FingerprintRuleCatalog(new ObjectMapper(), rulesFile.toString());
    assertThat(restarted.reload()).isEqualTo(info);
    assertThat(restarted.rules())
        .extracting(FingerprintRuleCatalog.Rule::id)
        .containsExactly("new");
  }

  @Test
  void persistsManagedOverrideWhenBuiltInCatalogIsTheInitialSource() throws Exception {
    Path managedFile = tempDirectory.resolve("managed").resolve("rules.json");
    String updated =
        """
        {"version":"managed-v1","rules":[{"id":"managed","name":"Managed","confidence":85}]}
        """;
    FingerprintRuleCatalog catalog =
        new FingerprintRuleCatalog(new ObjectMapper(), "", managedFile.toString());
    assertThat(catalog.reload().source()).isEqualTo(FingerprintRuleCatalog.CatalogSource.BUILTIN);

    FingerprintRuleCatalog.CatalogInfo info = catalog.update(updated.getBytes());

    assertThat(info.source()).isEqualTo(FingerprintRuleCatalog.CatalogSource.MANAGED);
    assertThat(Files.readString(managedFile)).isEqualTo(updated);

    FingerprintRuleCatalog restarted =
        new FingerprintRuleCatalog(new ObjectMapper(), "", managedFile.toString());
    assertThat(restarted.reload()).isEqualTo(info);
    assertThat(restarted.rules())
        .extracting(FingerprintRuleCatalog.Rule::id)
        .containsExactly("managed");
  }

  @Test
  void invalidUpdateKeepsPreviousCatalogAndFileUntouched(CapturedOutput output) throws Exception {
    String initial =
        """
        {"version":"stable","rules":[{"id":"stable","name":"Stable","confidence":80}]}
        """;
    Path rulesFile = tempDirectory.resolve("stable-rules.json");
    Files.writeString(rulesFile, initial);
    FingerprintRuleCatalog catalog =
        new FingerprintRuleCatalog(new ObjectMapper(), rulesFile.toString());
    FingerprintRuleCatalog.CatalogInfo previous = catalog.reload();

    assertThatThrownBy(() -> catalog.update("{not-json".getBytes()))
        .isInstanceOf(ApiException.class)
        .hasMessage("指纹规则更新失败，原有规则已保留")
        .hasMessageNotContaining("JsonParseException");

    assertThat(catalog.info()).isEqualTo(previous);
    assertThat(Files.readString(rulesFile)).isEqualTo(initial);
    assertThat(catalog.rules())
        .extracting(FingerprintRuleCatalog.Rule::id)
        .containsExactly("stable");
    assertThat(output).doesNotContain("not-json");
  }

  @Test
  void rejectsEmptyAndOversizedUpdatesWithoutChangingTheCatalog() throws Exception {
    String initial =
        """
        {"version":"stable","rules":[{"id":"stable","name":"Stable","confidence":80}]}
        """;
    Path rulesFile = tempDirectory.resolve("bounded-rules.json");
    Files.writeString(rulesFile, initial);
    FingerprintRuleCatalog catalog =
        new FingerprintRuleCatalog(new ObjectMapper(), rulesFile.toString());
    FingerprintRuleCatalog.CatalogInfo previous = catalog.reload();

    assertThatThrownBy(() -> catalog.update(new byte[0]))
        .isInstanceOf(ApiException.class)
        .hasMessage("指纹规则文件不能为空");
    assertThatThrownBy(() -> catalog.update(new byte[FingerprintRuleCatalog.MAX_BYTES + 1]))
        .isInstanceOf(ApiException.class)
        .hasMessage("指纹规则文件超过 2MB 限制");

    assertThat(catalog.info()).isEqualTo(previous);
    assertThat(Files.readString(rulesFile)).isEqualTo(initial);
  }

  private String sha256(String value) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes());
    return HexFormat.of().formatHex(digest);
  }
}

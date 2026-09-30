package io.github.bhanuharya.sonar.opengrep.sensor;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sonar.api.batch.fs.internal.DefaultInputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.rule.internal.ActiveRulesBuilder;
import org.sonar.api.batch.rule.internal.NewActiveRule;
import org.sonar.api.batch.sensor.internal.SensorContextTester;
import org.sonar.api.batch.sensor.issue.ExternalIssue;
import org.sonar.api.batch.sensor.issue.Issue;
import org.sonar.api.rule.RuleKey;
import org.sonar.api.rules.RuleType;

class OpenGrepSensorTest {

  @TempDir
  Path base;
  SensorContextTester context;

  @BeforeEach
  void setUp() {
    context = SensorContextTester.create(base);
    context.setActiveRules(new ActiveRulesBuilder()
      .addRule(new NewActiveRule.Builder().setRuleKey(RuleKey.of("opengrep-dart", "scp.dart.tls.bad-cert")).build())
      .addRule(new NewActiveRule.Builder().setRuleKey(RuleKey.of("opengrep-dart", "scp.dart.webview.js")).build())
      .build());
    context.fileSystem().add(file("lib/main.dart", "dart", "void main() {\n  a();\n  b();\n}"));
    context.fileSystem().add(file("android/app/src/main/AndroidManifest.xml", "xml", "<manifest/>\n"));
  }

  private DefaultInputFile file(String path, String language, String content) {
    return TestInputFileBuilder.create("module", path).setModuleBaseDir(base).setLanguage(language)
      .setContents(content).build();
  }

  private void report(String name, String json) throws Exception {
    Files.writeString(base.resolve(name), json);
    context.settings().appendProperty("sonar.opengrep.reportPaths", name);
  }

  @Test
  void opengrep_results_land_on_active_rules_even_with_a_config_prefix() throws Exception {
    report("opengrep.json", """
      {"results": [
        {"check_id": "rules.dart.scp.dart.tls.bad-cert", "path": "lib/main.dart",
         "start": {"line": 2}, "end": {"line": 3},
         "extra": {"message": "bad cert", "severity": "ERROR", "metadata": {"category": "security"}}},
        {"check_id": "scp.dart.webview.js", "path": "lib/main.dart",
         "start": {"line": 3}, "end": {"line": 3}, "extra": {"message": "js", "severity": "WARNING"}}
      ]}""");
    new OpenGrepSensor().execute(context);

    assertThat(context.allIssues()).extracting(Issue::ruleKey).containsExactlyInAnyOrder(
      RuleKey.of("opengrep-dart", "scp.dart.tls.bad-cert"), RuleKey.of("opengrep-dart", "scp.dart.webview.js"));
    Issue tls = context.allIssues().stream().filter(i -> i.ruleKey().rule().equals("scp.dart.tls.bad-cert")).findFirst().orElseThrow();
    assertThat(tls.primaryLocation().message()).isEqualTo("bad cert");
    assertThat(tls.primaryLocation().textRange().start().line()).isEqualTo(2);
    assertThat(tls.primaryLocation().textRange().end().line()).isEqualTo(3);
    assertThat(context.allExternalIssues()).isEmpty();
  }

  @Test
  void sdt_findings_import_only_the_opengrep_adapter() throws Exception {
    report("findings.json", """
      {"schemaVersion": "secure-dev/report/v1alpha1", "findings": [
        {"scanner": {"adapter": "opengrep"}, "rule": {"id": "scp.dart.tls.bad-cert"},
         "location": {"path": "lib/main.dart", "startLine": 2, "endLine": 2},
         "message": "bad cert", "severity": {"canonical": "high"}},
        {"scanner": {"adapter": "gitleaks"}, "rule": {"id": "generic-api-key"},
         "location": {"path": "lib/main.dart", "startLine": 1}, "message": "secret"}
      ]}""");
    new OpenGrepSensor().execute(context);

    assertThat(context.allIssues()).hasSize(1);
    assertThat(context.allExternalIssues()).isEmpty();
  }

  @Test
  void a_result_without_an_active_rule_falls_back_to_an_external_issue() throws Exception {
    report("opengrep.json", """
      {"results": [
        {"check_id": "android.debuggable", "path": "android/app/src/main/AndroidManifest.xml",
         "start": {"line": 1}, "end": {"line": 1},
         "extra": {"message": "debuggable", "severity": "ERROR", "metadata": {"cwe": ["CWE-489"]}}}
      ]}""");
    new OpenGrepSensor().execute(context);

    assertThat(context.allIssues()).isEmpty();
    ExternalIssue external = context.allExternalIssues().iterator().next();
    assertThat(external.engineId()).isEqualTo("opengrep");
    assertThat(external.ruleId()).isEqualTo("android.debuggable");
    assertThat(external.type()).isEqualTo(RuleType.VULNERABILITY);
  }

  @Test
  void the_fallback_can_be_disabled_and_unknown_files_are_skipped() throws Exception {
    context.settings().setProperty("sonar.opengrep.externalIssuesFallback", "false");
    report("opengrep.json", """
      {"results": [
        {"check_id": "android.debuggable", "path": "android/app/src/main/AndroidManifest.xml",
         "start": {"line": 1}, "extra": {"message": "m", "severity": "ERROR"}},
        {"check_id": "scp.dart.tls.bad-cert", "path": "lib/deleted.dart",
         "start": {"line": 1}, "extra": {"message": "m", "severity": "ERROR"}}
      ]}""");
    new OpenGrepSensor().execute(context);

    assertThat(context.allIssues()).isEmpty();
    assertThat(context.allExternalIssues()).isEmpty();
  }

  @Test
  void duplicates_collapse_and_lines_are_clamped_to_the_file() throws Exception {
    report("opengrep.json", """
      {"results": [
        {"check_id": "scp.dart.tls.bad-cert", "path": "lib/main.dart", "start": {"line": 40}, "end": {"line": 90},
         "extra": {"message": "m", "severity": "ERROR"}},
        {"check_id": "scp.dart.tls.bad-cert", "path": "lib/main.dart", "start": {"line": 40}, "end": {"line": 90},
         "extra": {"message": "m", "severity": "ERROR"}}
      ]}""");
    new OpenGrepSensor().execute(context);

    assertThat(context.allIssues()).hasSize(1);
    assertThat(context.allIssues().iterator().next().primaryLocation().textRange().start().line()).isEqualTo(4);
  }

  @Test
  void an_unreadable_report_is_logged_not_fatal() throws Exception {
    report("broken.json", "{not json");
    new OpenGrepSensor().execute(context);
    assertThat(context.allIssues()).isEmpty();
  }
}

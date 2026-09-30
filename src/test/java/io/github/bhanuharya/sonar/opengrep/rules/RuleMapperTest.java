package io.github.bhanuharya.sonar.opengrep.rules;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.sonar.api.rule.Severity;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.rule.RulesDefinition.OwaspTop10;
import org.sonar.api.server.rule.RulesDefinition.OwaspTop10Version;

class RuleMapperTest {

  static OpenGrepRule rule(String yaml) {
    List<OpenGrepRule> rules = RuleLoader.parse(
      new ByteArrayInputStream(("rules:\n" + yaml).getBytes(StandardCharsets.UTF_8)), "test.yaml");
    assertThat(rules).hasSize(1);
    return rules.get(0);
  }

  @Test
  void a_confident_security_rule_is_a_vulnerability() {
    OpenGrepRule r = rule("""
      - id: a.b.tls
        languages: [dart]
        message: m
        severity: ERROR
        metadata: {category: security, confidence: HIGH, cwe: ["CWE-295"]}
      """);
    assertThat(RuleMapper.type(r)).isEqualTo(RuleType.VULNERABILITY);
    assertThat(RuleMapper.severity(r)).isEqualTo(Severity.CRITICAL);
  }

  @Test
  void a_pattern_match_needing_context_is_a_hotspot() {
    OpenGrepRule r = rule("""
      - id: a.b.webview
        languages: [dart]
        message: m
        severity: WARNING
        metadata: {category: security, confidence: MEDIUM}
      """);
    assertThat(RuleMapper.type(r)).isEqualTo(RuleType.SECURITY_HOTSPOT);
  }

  @Test
  void a_taint_rule_is_a_vulnerability_whatever_its_confidence() {
    OpenGrepRule r = rule("""
      - id: a.b.sqli
        mode: taint
        languages: [java]
        message: m
        severity: WARNING
        metadata: {category: security, confidence: LOW}
      """);
    assertThat(RuleMapper.type(r)).isEqualTo(RuleType.VULNERABILITY);
  }

  @Test
  void an_explicit_sonar_type_wins_nested_or_flat() {
    OpenGrepRule nested = rule("""
      - id: a.nested
        languages: [dart]
        message: m
        severity: ERROR
        metadata: {category: security, confidence: HIGH, sonar: {type: hotspot}}
      """);
    OpenGrepRule flat = rule("""
      - id: a.flat
        languages: [dart]
        message: m
        severity: INFO
        metadata: {category: security, confidence: LOW, sonar-type: vulnerability}
      """);
    assertThat(RuleMapper.type(nested)).isEqualTo(RuleType.SECURITY_HOTSPOT);
    assertThat(RuleMapper.type(flat)).isEqualTo(RuleType.VULNERABILITY);
  }

  @Test
  void non_security_rules_are_bugs_or_code_smells() {
    assertThat(RuleMapper.type(rule("""
      - id: a.c
        languages: [go]
        message: m
        severity: INFO
        metadata: {category: correctness}
      """))).isEqualTo(RuleType.BUG);
    assertThat(RuleMapper.type(rule("""
      - id: a.s
        languages: [go]
        message: m
        severity: INFO
        metadata: {category: best-practice}
      """))).isEqualTo(RuleType.CODE_SMELL);
  }

  @Test
  void standards_are_parsed_from_the_usual_spellings() {
    OpenGrepRule r = rule("""
      - id: a.std
        languages: [java]
        message: m
        severity: ERROR
        metadata:
          category: security
          cwe: ["CWE-89: Improper Neutralization", "CWE-564"]
          owasp: ["A03:2021 - Injection", "A1:2017 - Injection", "M4: Insufficient Input/Output Validation (Mobile)"]
          owasp-mobile: ["M4: Insufficient Input/Output Validation"]
          masvs: ["MASVS-CODE-4"]
      """);
    assertThat(RuleMapper.cwes(r)).containsExactly(89, 564);
    assertThat(RuleMapper.owasp(r))
      .containsEntry(OwaspTop10Version.Y2021, Set.of(OwaspTop10.A3))
      .containsEntry(OwaspTop10Version.Y2017, Set.of(OwaspTop10.A1));
    assertThat(RuleMapper.tags(r)).contains("opengrep", "owasp-mobile-m4", "masvs-code-4");
  }

  @Test
  void only_dart_rules_are_dart_however_they_say_so() {
    assertThat(RuleMapper.isDart(rule("""
      - id: a
        languages: [dart]
        message: m
        severity: ERROR
      """))).isTrue();
    assertThat(RuleMapper.isDart(rule("""
      - id: b
        languages: [regex]
        paths: {include: ["lib/**/*.dart"]}
        message: m
        severity: ERROR
      """))).isTrue();
    assertThat(RuleMapper.isDart(rule("""
      - id: c
        languages: [generic]
        message: m
        severity: ERROR
        metadata: {sonar: {language: dart}}
      """))).isTrue();
    assertThat(RuleMapper.isDart(rule("""
      - id: d
        languages: [generic]
        paths: {include: ["**/AndroidManifest.xml"]}
        message: m
        severity: ERROR
      """))).isFalse();
    assertThat(RuleMapper.isDart(rule("""
      - id: e
        languages: [kotlin]
        message: m
        severity: ERROR
      """))).isFalse();
  }

  @Test
  void names_and_descriptions_are_readable_and_escaped() {
    OpenGrepRule r = rule("""
      - id: scp.dart.tls.disable-certificate-validation
        languages: [dart]
        message: "<b>bad</b> $X"
        severity: ERROR
        metadata:
          category: security
          cwe: ["CWE-295"]
          remediation: Pin the certificate.
          references: ["https://example.test/ref"]
      """);
    assertThat(RuleMapper.name(r)).isEqualTo("Disable certificate validation");
    assertThat(RuleMapper.htmlDescription(r))
      .contains("&lt;b&gt;bad&lt;/b&gt; $X")
      .contains("How to fix it")
      .contains("CWE-295")
      .contains("href=\"https://example.test/ref\"");
  }
}

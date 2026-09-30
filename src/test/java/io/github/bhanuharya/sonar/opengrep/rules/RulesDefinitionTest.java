package io.github.bhanuharya.sonar.opengrep.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sonar.api.config.internal.MapSettings;
import org.sonar.api.impl.server.RulesDefinitionContext;
import org.sonar.api.resources.Language;
import org.sonar.api.resources.Languages;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.profile.BuiltInQualityProfilesDefinition;
import org.sonar.api.server.rule.RulesDefinition;

class RulesDefinitionTest {

  private static Languages installed(String... keys) {
    Language[] languages = new Language[keys.length];
    for (int i = 0; i < keys.length; i++) {
      Language language = mock(Language.class);
      when(language.getKey()).thenReturn(keys[i]);
      when(language.getName()).thenReturn(keys[i]);
      languages[i] = language;
    }
    return new Languages(languages);
  }

  private static List<OpenGrepRule> parse(String yaml) {
    return RuleLoader.parse(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)), "t.yaml");
  }

  @Test
  void the_bundled_pack_loads_and_types_the_dart_rules() {
    MapSettings settings = new MapSettings();
    RulesDefinitionContext context = new RulesDefinitionContext();
    new OpenGrepRulesDefinition(settings.asConfig(), installed("dart")).define(context);

    RulesDefinition.Repository repo = context.repository("opengrep-dart");
    assertThat(repo).isNotNull();
    assertThat(repo.language()).isEqualTo("dart");
    RulesDefinition.Rule tls = repo.rule("scp.dart.tls.disable-certificate-validation");
    assertThat(tls.type()).isEqualTo(RuleType.VULNERABILITY);
    assertThat(tls.securityStandards()).contains("cwe:295", "owaspTop10-2021:a2");
    RulesDefinition.Rule webview = repo.rule("scp.dart.webview.javascript-unrestricted");
    assertThat(webview.type()).isEqualTo(RuleType.SECURITY_HOTSPOT);
  }

  @Test
  void without_a_dart_plugin_nothing_is_published() {
    RulesDefinitionContext context = new RulesDefinitionContext();
    new OpenGrepRulesDefinition(new MapSettings().asConfig(), installed("java", "kotlin")).define(context);
    assertThat(context.repositories()).isEmpty();
  }

  @Test
  void configured_directories_add_dart_rules_only_and_the_first_definition_wins(@TempDir Path dir) throws Exception {
    Files.writeString(dir.resolve("custom.yaml"), """
      rules:
        - id: my.dart.rule
          languages: [dart]
          message: m
          severity: WARNING
          metadata: {category: security}
        - id: my.kotlin.rule
          languages: [kotlin]
          message: m
          severity: WARNING
          metadata: {category: security}
        - id: scp.dart.tls.disable-certificate-validation
          languages: [dart]
          message: duplicate
          severity: INFO
      """);
    Files.writeString(dir.resolve("not-rules.yml"), "name: just some yaml\n");
    Files.writeString(dir.resolve("broken.yaml"), "rules: [\n");
    MapSettings settings = new MapSettings()
      .setProperty("sonar.opengrep.rules.directories", dir.toString());
    RulesDefinitionContext context = new RulesDefinitionContext();
    new OpenGrepRulesDefinition(settings.asConfig(), installed("dart", "kotlin")).define(context);

    RulesDefinition.Repository dart = context.repository("opengrep-dart");
    assertThat(dart.rule("my.dart.rule").type()).isEqualTo(RuleType.SECURITY_HOTSPOT);
    assertThat(dart.rule("scp.dart.tls.disable-certificate-validation").severity()).isEqualTo("CRITICAL");
    assertThat(context.repository("opengrep-kotlin")).isNull();
    assertThat(context.repositories()).hasSize(1);
  }

  @Test
  void the_bundled_pack_can_be_switched_off(@TempDir Path dir) {
    MapSettings settings = new MapSettings().setProperty("sonar.opengrep.rules.bundled", "false");
    RulesDefinitionContext context = new RulesDefinitionContext();
    new OpenGrepRulesDefinition(settings.asConfig(), installed("dart")).define(context);
    assertThat(context.repositories()).isEmpty();
  }

  @Test
  void the_dart_profile_activates_every_dart_rule() {
    Map<String, List<OpenGrepRule>> catalog = RuleCatalog.byLanguage(parse("""
      rules:
        - id: a
          languages: [dart]
          message: m
          severity: ERROR
        - id: b
          languages: [javascript, typescript]
          message: m
          severity: ERROR
      """), installed("dart", "js", "ts"));
    BuiltInQualityProfilesDefinition.Context context = new BuiltInQualityProfilesDefinition.Context();
    OpenGrepProfilesDefinition.define(context, catalog);

    assertThat(context.profile("dart", "OpenGrep Security").rules()).extracting(r -> r.ruleKey()).containsExactly("a");
    assertThat(context.profile("ts", "OpenGrep Security")).isNull();
  }
}

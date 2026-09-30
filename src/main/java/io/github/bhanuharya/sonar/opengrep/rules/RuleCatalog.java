package io.github.bhanuharya.sonar.opengrep.rules;

import io.github.bhanuharya.sonar.opengrep.OpenGrepProperties;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.sonar.api.config.Configuration;
import org.sonar.api.resources.Languages;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

/**
 * The rules this server publishes: the Dart rules of the bundled pack plus any
 * configured directories, provided some installed plugin (sonar-flutter) offers Dart.
 * A rule id defined twice keeps its first definition (directories are read in the
 * order configured, after the bundled pack).
 */
public final class RuleCatalog {

  private static final Logger LOG = Loggers.get(RuleCatalog.class);
  public static final String REPOSITORY_PREFIX = "opengrep-";

  private RuleCatalog() {
  }

  public static String repositoryKey(String language) {
    return REPOSITORY_PREFIX + language;
  }

  public static Map<String, List<OpenGrepRule>> load(Configuration config, Languages languages) {
    List<OpenGrepRule> all = new ArrayList<>();
    if (config.getBoolean(OpenGrepProperties.BUNDLED_RULES).orElse(true)) {
      all.addAll(RuleLoader.bundled());
    }
    for (String dir : config.getStringArray(OpenGrepProperties.RULE_DIRECTORIES)) {
      if (!dir.isBlank()) {
        all.addAll(RuleLoader.directory(Path.of(dir.trim())));
      }
    }
    return byLanguage(all, languages);
  }

  /** Language key -> rules. Only "dart" ever appears, and only when a plugin provides it. */
  static Map<String, List<OpenGrepRule>> byLanguage(List<OpenGrepRule> rules, Languages languages) {
    if (languages.get(RuleMapper.DART) == null) {
      LOG.warn("OpenGrep: no plugin provides the dart language (install sonar-flutter); no rules published");
      return Map.of();
    }
    Map<String, OpenGrepRule> dart = new LinkedHashMap<>();
    int other = 0;
    for (OpenGrepRule rule : rules) {
      if (!RuleMapper.isDart(rule)) {
        other++;
        LOG.debug("OpenGrep: rule {} ({}) is not a Dart rule; skipped", rule.id(), rule.source());
        continue;
      }
      OpenGrepRule previous = dart.putIfAbsent(rule.id(), rule);
      if (previous != null && !previous.source().equals(rule.source())) {
        LOG.warn("OpenGrep: rule {} is defined in both {} and {}; keeping the first", rule.id(),
          previous.source(), rule.source());
      }
    }
    LOG.info("OpenGrep: {} Dart rules ({} rules for other languages skipped)", dart.size(), other);
    return dart.isEmpty() ? Map.of() : Map.of(RuleMapper.DART, List.copyOf(dart.values()));
  }
}

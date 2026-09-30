package io.github.bhanuharya.sonar.opengrep.rules;

import io.github.bhanuharya.sonar.opengrep.OpenGrepProperties;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.sonar.api.config.Configuration;
import org.sonar.api.resources.Languages;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

/**
 * The rules this server publishes, grouped by Sonar language: the bundled pack plus
 * any configured directories. Only Dart is published unless
 * {@code sonar.opengrep.languages} enables more ("*" for every installed language),
 * and only for languages some installed plugin provides. A rule id defined twice in
 * one language keeps its first definition (bundled pack first, then directories in
 * the order configured).
 */
public final class RuleCatalog {

  private static final Logger LOG = Loggers.get(RuleCatalog.class);
  public static final String REPOSITORY_PREFIX = "opengrep-";
  public static final String ALL_LANGUAGES = "*";

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
    Set<String> enabled = new HashSet<>();
    for (String language : config.getStringArray(OpenGrepProperties.LANGUAGES)) {
      if (!language.isBlank()) {
        enabled.add(language.trim().toLowerCase(Locale.ROOT));
      }
    }
    return byLanguage(all, languages, enabled.isEmpty() ? Set.of(RuleMapper.DART) : enabled);
  }

  /** Dart only: the default. */
  static Map<String, List<OpenGrepRule>> byLanguage(List<OpenGrepRule> rules, Languages languages) {
    return byLanguage(rules, languages, Set.of(RuleMapper.DART));
  }

  /** Language key -> rules, for the enabled languages ("*" = all) that some plugin provides. */
  static Map<String, List<OpenGrepRule>> byLanguage(List<OpenGrepRule> rules, Languages languages,
    Set<String> enabled) {
    boolean all = enabled.contains(ALL_LANGUAGES);
    Map<String, Map<String, OpenGrepRule>> grouped = new TreeMap<>();
    int skipped = 0;
    for (OpenGrepRule rule : rules) {
      boolean placed = false;
      for (String language : RuleMapper.languages(rule)) {
        if ((!all && !enabled.contains(language)) || languages.get(language) == null) {
          continue;
        }
        placed = true;
        Map<String, OpenGrepRule> repo = grouped.computeIfAbsent(language, key -> new LinkedHashMap<>());
        OpenGrepRule previous = repo.putIfAbsent(rule.id(), rule);
        if (previous != null && !previous.source().equals(rule.source())) {
          LOG.warn("OpenGrep: rule {} is defined in both {} and {}; keeping the first", rule.id(),
            previous.source(), rule.source());
        }
      }
      if (!placed) {
        skipped++;
        LOG.debug("OpenGrep: rule {} ({}) targets no enabled, installed language", rule.id(), rule.source());
      }
    }
    if (enabled.contains(RuleMapper.DART) && languages.get(RuleMapper.DART) == null) {
      LOG.warn("OpenGrep: no plugin provides the dart language (install sonar-flutter); no Dart rules published");
    }
    Map<String, List<OpenGrepRule>> result = new TreeMap<>();
    grouped.forEach((language, repo) -> result.put(language, List.copyOf(repo.values())));
    LOG.info("OpenGrep: {} rules in {} ({} rules for other or uninstalled languages skipped)",
      result.values().stream().mapToInt(List::size).sum(), result.keySet(), skipped);
    return result;
  }
}

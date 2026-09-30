package io.github.bhanuharya.sonar.opengrep.rules;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.sonar.api.config.Configuration;
import org.sonar.api.resources.Languages;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.rule.RulesDefinition;

/** One "OpenGrep" rule repository per installed language that has rules. */
public class OpenGrepRulesDefinition implements RulesDefinition {

  private final Configuration config;
  private final Languages languages;

  public OpenGrepRulesDefinition(Configuration config, Languages languages) {
    this.config = config;
    this.languages = languages;
  }

  @Override
  public void define(Context context) {
    define(context, RuleCatalog.load(config, languages));
    String home = SdtRules.home(languages);
    if (home != null) {
      NewRepository repo = context.createRepository(SdtRules.REPOSITORY, home).setName("SDT");
      SdtRules.define(repo);
      repo.done();
    }
  }

  static void define(Context context, Map<String, List<OpenGrepRule>> catalog) {
    catalog.forEach((language, rules) -> {
      NewRepository repo = context.createRepository(RuleCatalog.repositoryKey(language), language).setName("OpenGrep");
      rules.forEach(rule -> addRule(repo, rule));
      repo.done();
    });
  }

  private static void addRule(NewRepository repo, OpenGrepRule rule) {
    RuleType type = RuleMapper.type(rule);
    NewRule sonarRule = repo.createRule(rule.id())
      .setName(RuleMapper.name(rule))
      .setHtmlDescription(RuleMapper.htmlDescription(rule))
      .setType(type)
      .setSeverity(RuleMapper.severity(rule));
    Set<String> tags = RuleMapper.tags(rule);
    sonarRule.addTags(tags.toArray(String[]::new));
    List<Integer> cwes = RuleMapper.cwes(rule);
    if (!cwes.isEmpty()) {
      sonarRule.addCwe(cwes.stream().mapToInt(Integer::intValue).toArray());
    }
    RuleMapper.owasp(rule).forEach((version, categories) ->
      sonarRule.addOwaspTop10(version, categories.toArray(OwaspTop10[]::new)));
  }
}

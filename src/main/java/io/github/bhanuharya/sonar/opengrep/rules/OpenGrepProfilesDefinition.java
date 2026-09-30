package io.github.bhanuharya.sonar.opengrep.rules;

import java.util.List;
import java.util.Map;
import org.sonar.api.config.Configuration;
import org.sonar.api.resources.Languages;
import org.sonar.api.server.profile.BuiltInQualityProfilesDefinition;

/**
 * A built-in "OpenGrep Security" profile per language, activating every OpenGrep rule.
 *
 * <p>A project uses one profile per language, so to keep a language plugin's own rules
 * as well, create a profile that inherits from that plugin's default and activate the
 * OpenGrep repository in it (see scripts/setup-quality-profile.sh). Built-in profiles
 * cannot extend each other, and one plugin cannot add rules to another's built-in
 * profile, which is why this is a script and not a default.
 */
public class OpenGrepProfilesDefinition implements BuiltInQualityProfilesDefinition {

  public static final String PROFILE_NAME = "OpenGrep Security";

  private final Configuration config;
  private final Languages languages;

  public OpenGrepProfilesDefinition(Configuration config, Languages languages) {
    this.config = config;
    this.languages = languages;
  }

  @Override
  public void define(Context context) {
    define(context, RuleCatalog.load(config, languages));
  }

  static void define(Context context, Map<String, List<OpenGrepRule>> catalog) {
    catalog.forEach((language, rules) -> {
      NewBuiltInQualityProfile profile = context.createBuiltInQualityProfile(PROFILE_NAME, language);
      rules.forEach(rule -> profile.activateRule(RuleCatalog.repositoryKey(language), rule.id()));
      profile.done();
    });
  }
}

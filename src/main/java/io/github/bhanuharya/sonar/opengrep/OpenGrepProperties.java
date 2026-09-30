package io.github.bhanuharya.sonar.opengrep;

import java.util.List;
import org.sonar.api.PropertyType;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.resources.Qualifiers;

/** Every setting the plugin reads, with its documentation. */
public final class OpenGrepProperties {

  public static final String CATEGORY = "OpenGrep";

  /** Scanner side: OpenGrep/Semgrep JSON or SDT findings.json reports to import. */
  public static final String REPORT_PATHS = "sonar.opengrep.reportPaths";
  /** Scanner side: import results with no matching active rule as external issues. */
  public static final String EXTERNAL_FALLBACK = "sonar.opengrep.externalIssuesFallback";
  /** Server side (sonar.properties): extra rule directories loaded at startup. */
  public static final String RULE_DIRECTORIES = "sonar.opengrep.rules.directories";
  /** Server side (sonar.properties): set to false to publish only rules from RULE_DIRECTORIES. */
  public static final String BUNDLED_RULES = "sonar.opengrep.rules.bundled";

  private OpenGrepProperties() {
  }

  public static List<PropertyDefinition> definitions() {
    return List.of(
      PropertyDefinition.builder(REPORT_PATHS)
        .name("Report paths")
        .description("Comma-separated paths to OpenGrep/Semgrep JSON reports (opengrep --json) or SDT "
          + "findings.json files, relative to the project base directory or absolute.")
        .category(CATEGORY)
        .onQualifiers(Qualifiers.PROJECT)
        .multiValues(true)
        .build(),
      PropertyDefinition.builder(EXTERNAL_FALLBACK)
        .name("Import unknown results as external issues")
        .description("A result whose rule is not defined or not active in the quality profile is imported "
          + "as an external issue instead of being dropped. External issues cannot be Security Hotspots.")
        .category(CATEGORY)
        .onQualifiers(Qualifiers.PROJECT)
        .type(PropertyType.BOOLEAN)
        .defaultValue("true")
        .build());
  }
}

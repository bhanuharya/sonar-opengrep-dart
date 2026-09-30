package io.github.bhanuharya.sonar.opengrep.rules;

import java.util.List;
import org.sonar.api.resources.Languages;
import org.sonar.api.rule.Severity;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.rule.RulesDefinition.NewRepository;
import org.sonar.api.server.rule.RulesDefinition.NewRule;
import org.sonar.api.server.rule.RulesDefinition.OwaspTop10;
import org.sonar.api.server.rule.RulesDefinition.OwaspTop10Version;

/**
 * Native rules for the findings SDT reports besides OpenGrep: committed secrets (gitleaks)
 * and vulnerable dependencies (Trivy). They are not tied to a programming language, so
 * they live on the "secrets" language (sonar-text), whose profile every project loads;
 * "text" is the fallback home.
 */
public final class SdtRules {

  public static final String REPOSITORY = "sdt";
  public static final String SECRET = "secret";
  public static final String SECRET_IN_HISTORY = "secret-in-history";
  public static final String VULNERABLE_DEPENDENCY = "vulnerable-dependency";
  public static final String UNREACHABLE_DEPENDENCY = "vulnerable-dependency-unreachable";
  public static final List<String> KEYS = List.of(SECRET, SECRET_IN_HISTORY, VULNERABLE_DEPENDENCY, UNREACHABLE_DEPENDENCY);
  private static final List<String> HOMES = List.of("secrets", "text");

  private SdtRules() {
  }

  /** The language the SDT rules live on, or null when neither home is installed. */
  public static String home(Languages languages) {
    return HOMES.stream().filter(key -> languages.get(key) != null).findFirst().orElse(null);
  }

  static void define(NewRepository repo) {
    rule(repo, SECRET, "Secrets should not be committed to source code", RuleType.VULNERABILITY, Severity.BLOCKER,
      "<p>A credential (API key, password, token or private key) is written in a file in the repository. Anyone "
        + "who can read the repository, its forks, backups or build logs can use it.</p>"
        + "<h2>How to fix it</h2><ol><li>Revoke and rotate the credential first: it is already exposed.</li>"
        + "<li>Load it at runtime from the CI/CD secret store or a vault instead of source code.</li>"
        + "<li>Remove it from the file. Deleting it does not remove it from git history.</li></ol>",
      new int[] {798}, OwaspTop10.A7, "secrets", "gitleaks");
    rule(repo, SECRET_IN_HISTORY, "Secrets in git history should be rotated", RuleType.VULNERABILITY, Severity.CRITICAL,
      "<p>A credential was committed in the past. The file or line no longer contains it, but every clone of the "
        + "repository still does, so it must be treated as leaked. The issue is raised on the project because the "
        + "file it was found in is not part of the current checkout.</p>"
        + "<h2>How to fix it</h2><ol><li>Revoke and rotate the credential. Rewriting history is not enough on "
        + "its own: existing clones keep it.</li><li>Record the rotation, then mark this issue resolved.</li>"
        + "<li>Add a pre-commit secret scan so it cannot happen again.</li></ol>",
      new int[] {798, 540}, OwaspTop10.A7, "secrets", "gitleaks", "git-history");
    rule(repo, VULNERABLE_DEPENDENCY, "Dependencies with known vulnerabilities should be upgraded",
      RuleType.VULNERABILITY, Severity.MAJOR,
      "<p>The project depends on a package version with a published vulnerability, and the package is used "
        + "by the code (or its use could not be ruled out).</p>"
        + "<h2>How to fix it</h2><p>Upgrade to the fixed version named in the issue. If no fix exists, check the "
        + "advisory for a workaround and whether the vulnerable function is used.</p>",
      new int[] {1395}, OwaspTop10.A6, "dependency", "trivy");
    rule(repo, UNREACHABLE_DEPENDENCY, "Vulnerable dependencies not imported by the code should be reviewed",
      RuleType.SECURITY_HOTSPOT, Severity.MAJOR,
      "<p>A dependency has a published vulnerability, but static analysis found no source file that imports "
        + "the package. It may be a build tool, a transitive dependency or dead weight, so a human should confirm "
        + "it is not reachable at runtime.</p>"
        + "<h2>How to fix it</h2><p>Upgrade it anyway when a fix exists, or remove it if unused. Mark the hotspot "
        + "Safe only after confirming it is not loaded at runtime.</p>",
      new int[] {1395}, OwaspTop10.A6, "dependency", "trivy", "unreachable");
  }

  private static void rule(NewRepository repo, String key, String name, RuleType type, String severity, String html,
    int[] cwe, OwaspTop10 owasp, String... tags) {
    NewRule rule = repo.createRule(key).setName(name).setHtmlDescription(html).setType(type).setSeverity(severity);
    rule.addTags(tags).addCwe(cwe).addOwaspTop10(OwaspTop10Version.Y2021, owasp);
  }
}

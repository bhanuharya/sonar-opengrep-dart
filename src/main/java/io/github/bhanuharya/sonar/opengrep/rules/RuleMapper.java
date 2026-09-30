package io.github.bhanuharya.sonar.opengrep.rules;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.sonar.api.rule.Severity;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.rule.RulesDefinition.OwaspTop10;
import org.sonar.api.server.rule.RulesDefinition.OwaspTop10Version;

/**
 * How an OpenGrep rule becomes a Sonar rule. Every decision here is documented in
 * the README's "Rule metadata" section; keep the two in step.
 */
public final class RuleMapper {

  /** The default Sonar language (provided by sonar-flutter); others are opt-in. */
  public static final String DART = "dart";

  /** OpenGrep language name -> Sonar language key, for the opt-in languages. */
  private static final Map<String, String> LANGUAGES = Map.ofEntries(
    Map.entry("dart", "dart"),
    Map.entry("java", "java"),
    Map.entry("kotlin", "kotlin"), Map.entry("kt", "kotlin"),
    Map.entry("python", "py"), Map.entry("py", "py"), Map.entry("python3", "py"),
    Map.entry("javascript", "js"), Map.entry("js", "js"),
    Map.entry("typescript", "ts"), Map.entry("ts", "ts"),
    Map.entry("go", "go"), Map.entry("golang", "go"),
    Map.entry("php", "php"),
    Map.entry("ruby", "ruby"), Map.entry("rb", "ruby"),
    Map.entry("csharp", "cs"), Map.entry("c#", "cs"),
    Map.entry("scala", "scala"),
    Map.entry("swift", "swift"),
    Map.entry("c", "c"), Map.entry("cpp", "cpp"), Map.entry("c++", "cpp"),
    Map.entry("rust", "rust"),
    Map.entry("html", "web"),
    Map.entry("xml", "xml"),
    Map.entry("terraform", "terraform"), Map.entry("hcl", "terraform"),
    Map.entry("dockerfile", "docker"), Map.entry("docker", "docker"),
    Map.entry("json", "json"),
    Map.entry("yaml", "yaml"));

  /** For generic/regex rules: the file suffix in paths.include -> Sonar language key. */
  private static final Map<String, String> SUFFIXES = Map.ofEntries(
    Map.entry(".dart", "dart"), Map.entry(".xml", "xml"), Map.entry(".plist", "xml"),
    Map.entry(".kt", "kotlin"), Map.entry(".kts", "kotlin"), Map.entry(".java", "java"),
    Map.entry(".py", "py"), Map.entry(".js", "js"), Map.entry(".ts", "ts"), Map.entry(".go", "go"),
    Map.entry(".yaml", "yaml"), Map.entry(".yml", "yaml"), Map.entry(".json", "json"),
    Map.entry(".tf", "terraform"), Map.entry("dockerfile", "docker"));

  /**
   * The Sonar languages a rule belongs to: an explicit {@code sonar.language}, else its
   * OpenGrep languages, else (generic/regex rules) the file suffixes it targets.
   */
  public static Set<String> languages(OpenGrepRule rule) {
    Set<String> keys = new LinkedHashSet<>();
    for (String explicit : rule.metaList("sonar.language")) {
      keys.add(explicit.toLowerCase(Locale.ROOT));
    }
    if (!keys.isEmpty()) {
      return keys;
    }
    for (String language : rule.languages()) {
      String key = LANGUAGES.get(language);
      if (key != null) {
        keys.add(key);
      }
    }
    if (keys.isEmpty()) {
      for (String glob : rule.includes()) {
        String lower = glob.toLowerCase(Locale.ROOT);
        SUFFIXES.forEach((suffix, key) -> {
          if (lower.endsWith(suffix)) {
            keys.add(key);
          }
        });
      }
    }
    return keys;
  }

  private static final Pattern CWE = Pattern.compile("(?i)CWE-(\\d+)");
  private static final Pattern OWASP = Pattern.compile("(?i)\\bA(\\d{1,2})(?::(\\d{4}))?\\b");
  private static final Pattern TAG_UNSAFE = Pattern.compile("[^a-z0-9+#.-]+");

  private RuleMapper() {
  }

  /** True when the rule targets Dart (by language, explicit sonar.language, or *.dart globs). */
  public static boolean isDart(OpenGrepRule rule) {
    return languages(rule).contains(DART);
  }

  /**
   * Vulnerability or Security Hotspot (or Bug / Code Smell for non-security rules).
   *
   * <p>An explicit {@code sonar.type} always wins. Otherwise a security rule is a
   * Vulnerability when it is trustworthy on its own (confidence HIGH, or a taint rule
   * that follows data from a source to a sink) and a Hotspot when a human must look at
   * the context to decide.
   */
  public static RuleType type(OpenGrepRule rule) {
    String explicit = rule.metaString("sonar.type").toLowerCase(Locale.ROOT).replace('-', '_');
    switch (explicit) {
      case "vulnerability":
        return RuleType.VULNERABILITY;
      case "hotspot":
      case "security_hotspot":
        return RuleType.SECURITY_HOTSPOT;
      case "bug":
        return RuleType.BUG;
      case "code_smell":
        return RuleType.CODE_SMELL;
      default:
        break;
    }
    if (isSecurity(rule)) {
      boolean confident = "HIGH".equalsIgnoreCase(rule.metaString("confidence"));
      return confident || rule.taint() ? RuleType.VULNERABILITY : RuleType.SECURITY_HOTSPOT;
    }
    String category = rule.metaString("category").toLowerCase(Locale.ROOT);
    return category.equals("correctness") || category.equals("bug") ? RuleType.BUG : RuleType.CODE_SMELL;
  }

  /** True when the rule is about security, by category or by carrying a CWE. */
  public static boolean isSecurity(OpenGrepRule rule) {
    return "security".equalsIgnoreCase(rule.metaString("category")) || !cwes(rule).isEmpty();
  }

  /** The Sonar severity; an explicit {@code sonar.severity} wins over the OpenGrep one. */
  public static String severity(OpenGrepRule rule) {
    String explicit = rule.metaString("sonar.severity").toUpperCase(Locale.ROOT);
    if (Severity.ALL.contains(explicit)) {
      return explicit;
    }
    return severity(rule.severity());
  }

  /** An OpenGrep/Semgrep result severity as a Sonar severity. */
  public static String severity(String openGrepSeverity) {
    switch (openGrepSeverity == null ? "" : openGrepSeverity.toUpperCase(Locale.ROOT)) {
      case "CRITICAL":
        return Severity.BLOCKER;
      case "ERROR":
      case "HIGH":
        return Severity.CRITICAL;
      case "INFO":
      case "LOW":
      case "INVENTORY":
      case "EXPERIMENT":
        return Severity.MINOR;
      default:
        return Severity.MAJOR;
    }
  }

  /** CWE numbers from metadata.cwe ("CWE-295" or "CWE-295: Improper ..."). */
  public static List<Integer> cwes(OpenGrepRule rule) {
    Set<Integer> ids = new LinkedHashSet<>();
    for (String value : rule.metaList("cwe")) {
      Matcher m = CWE.matcher(value);
      while (m.find()) {
        ids.add(Integer.parseInt(m.group(1)));
      }
    }
    return new ArrayList<>(ids);
  }

  /** OWASP Top 10 categories from metadata.owasp, by edition. A year-less "A03" means 2021. */
  public static Map<OwaspTop10Version, Set<OwaspTop10>> owasp(OpenGrepRule rule) {
    Map<OwaspTop10Version, Set<OwaspTop10>> result = new EnumMap<>(OwaspTop10Version.class);
    for (String value : rule.metaList("owasp")) {
      if (value.toLowerCase(Locale.ROOT).contains("mobile")) {
        continue;
      }
      Matcher m = OWASP.matcher(value);
      if (!m.find()) {
        continue;
      }
      int number = Integer.parseInt(m.group(1));
      String year = m.group(2);
      OwaspTop10Version version = "2017".equals(year) ? OwaspTop10Version.Y2017 : OwaspTop10Version.Y2021;
      if ((year == null || year.equals("2017") || year.equals("2021")) && number >= 1 && number <= 10) {
        result.computeIfAbsent(version, v -> new LinkedHashSet<>()).add(OwaspTop10.valueOf("A" + number));
      }
    }
    return result;
  }

  /**
   * Tags: "opengrep", the OWASP Mobile Top 10 and MASVS references (Sonar has no
   * built-in standard for those), and any metadata.tags. CWE and OWASP Top 10 are not
   * tags: they are security standards, which Sonar's security reports read.
   */
  public static Set<String> tags(OpenGrepRule rule) {
    Set<String> tags = new LinkedHashSet<>();
    tags.add("opengrep");
    for (String value : rule.metaList("owasp-mobile")) {
      tags.add(tag("owasp-mobile-" + value.split("[:\\s]")[0]));
    }
    for (String value : rule.metaList("owasp")) {
      if (value.toLowerCase(Locale.ROOT).contains("mobile")) {
        Matcher m = Pattern.compile("(?i)\\bM(\\d{1,2})\\b").matcher(value);
        if (m.find()) {
          tags.add("owasp-mobile-m" + m.group(1));
        }
      }
    }
    for (String value : rule.metaList("masvs")) {
      tags.add(tag(value.split("[:\\s]")[0]));
    }
    for (String value : rule.metaList("tags")) {
      tags.add(tag(value));
    }
    tags.remove("");
    return tags;
  }

  private static String tag(String value) {
    return TAG_UNSAFE.matcher(value.trim().toLowerCase(Locale.ROOT)).replaceAll("-").replaceAll("^-+|-+$", "");
  }

  /** A short rule name: metadata.name / sonar.name, else the id's last segment in words. */
  public static String name(OpenGrepRule rule) {
    String explicit = rule.metaString("sonar.name");
    if (explicit.isEmpty()) {
      explicit = rule.metaString("name");
    }
    if (!explicit.isEmpty()) {
      return truncate(explicit, 200);
    }
    String[] segments = rule.id().split("\\.");
    String last = segments[segments.length - 1].replace('-', ' ').replace('_', ' ').trim();
    String words = last.isEmpty() ? rule.id() : Character.toUpperCase(last.charAt(0)) + last.substring(1);
    return truncate(words, 200);
  }

  /** The HTML description: message, remediation, standards, references, provenance. */
  public static String htmlDescription(OpenGrepRule rule) {
    StringBuilder html = new StringBuilder();
    String description = rule.metaString("description");
    html.append("<p>").append(escape(description.isEmpty() ? rule.message() : description)).append("</p>");
    String remediation = rule.metaString("remediation");
    if (remediation.isEmpty()) {
      remediation = rule.metaString("fix");
    }
    if (!remediation.isEmpty()) {
      html.append("<h2>How to fix it</h2><p>").append(escape(remediation)).append("</p>");
    }
    List<String> standards = new ArrayList<>();
    cwes(rule).forEach(id -> standards.add("<a href=\"https://cwe.mitre.org/data/definitions/" + id
      + ".html\">CWE-" + id + "</a>"));
    rule.metaList("owasp").forEach(value -> standards.add(escape(value)));
    rule.metaList("owasp-mobile").forEach(value -> standards.add("OWASP Mobile " + escape(value)));
    rule.metaList("masvs").forEach(value -> standards.add(escape(value)));
    if (!standards.isEmpty()) {
      html.append("<h2>Standards</h2><ul>");
      standards.forEach(item -> html.append("<li>").append(item).append("</li>"));
      html.append("</ul>");
    }
    List<String> references = rule.metaList("references");
    if (!references.isEmpty()) {
      html.append("<h2>References</h2><ul>");
      for (String ref : references) {
        String safe = escape(ref);
        html.append(ref.startsWith("http") ? "<li><a href=\"" + safe + "\">" + safe + "</a></li>" : "<li>" + safe + "</li>");
      }
      html.append("</ul>");
    }
    html.append("<p><small>OpenGrep rule <code>").append(escape(rule.id())).append("</code>");
    String confidence = rule.metaString("confidence");
    if (!confidence.isEmpty()) {
      html.append(", confidence ").append(escape(confidence));
    }
    html.append(".</small></p>");
    return html.toString();
  }

  static String escape(String text) {
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
  }

  private static String truncate(String text, int max) {
    return text.length() <= max ? text : text.substring(0, max - 1) + "…";
  }
}

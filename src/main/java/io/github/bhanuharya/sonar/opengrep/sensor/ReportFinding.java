package io.github.bhanuharya.sonar.opengrep.sensor;

/**
 * One result from a report, independent of the report's format.
 *
 * @param kind        what produced it: an OpenGrep rule, a secret scanner, or a dependency scanner
 * @param ruleId      the rule id as the report spells it (OpenGrep may prefix it with the config path)
 * @param path        the file path as reported (relative to the scan root, or absolute); may be empty
 * @param startLine   1-based, or 0 when the report gives no line
 * @param endLine     1-based, or 0 when unknown
 * @param message     the result message
 * @param severity    the reported severity (OpenGrep or SDT vocabulary)
 * @param security    whether the report marks the result as a security finding
 * @param commit      secrets: the commit the secret was found in, or empty
 * @param dependency  dependencies: package, versions and reachability, or null
 */
public record ReportFinding(Kind kind, String ruleId, String path, int startLine, int endLine, String message,
  String severity, boolean security, String commit, Dependency dependency) {

  public enum Kind { OPENGREP, SECRET, DEPENDENCY }

  /** Convenience for OpenGrep results. */
  public static ReportFinding openGrep(String ruleId, String path, int startLine, int endLine, String message,
    String severity, boolean security) {
    return new ReportFinding(Kind.OPENGREP, ruleId, path, startLine, endLine, message, severity, security, "", null);
  }

  /**
   * @param name        package name
   * @param installed   installed version
   * @param fixed       fixed version, or empty
   * @param unreachable true when static analysis found no source importing the package
   */
  public record Dependency(String name, String installed, String fixed, boolean unreachable) {
  }
}

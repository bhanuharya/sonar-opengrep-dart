package io.github.bhanuharya.sonar.opengrep.sensor;

/**
 * One result from a report, independent of the report's format.
 *
 * @param ruleId    the rule id as the report spells it (OpenGrep may prefix it with the config path)
 * @param path      the file path as reported (relative to the scan root, or absolute)
 * @param startLine 1-based, or 0 when the report gives no line
 * @param endLine   1-based, or 0 when unknown
 * @param message   the result message
 * @param severity  the reported severity (OpenGrep or SDT vocabulary)
 * @param security  whether the report marks the result as a security finding
 */
public record ReportFinding(String ruleId, String path, int startLine, int endLine, String message,
  String severity, boolean security) {
}

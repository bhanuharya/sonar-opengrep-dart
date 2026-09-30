package io.github.bhanuharya.sonar.opengrep.rules;

import java.util.List;
import java.util.Map;

/**
 * One rule as written in an OpenGrep/Semgrep YAML file: only the fields the plugin maps.
 *
 * @param id        the rule id, which becomes the Sonar rule key
 * @param message   the finding message (may contain $METAVARIABLES)
 * @param severity  OpenGrep severity (ERROR, WARNING, INFO, or CRITICAL/HIGH/MEDIUM/LOW)
 * @param languages OpenGrep languages, lower-cased
 * @param metadata  the free-form metadata block
 * @param includes  the paths.include globs, used to place generic rules on a language
 * @param taint     true for mode: taint rules (data-flow, not pattern matches)
 * @param source    where the rule was loaded from, for diagnostics
 */
public record OpenGrepRule(String id, String message, String severity, List<String> languages,
  Map<String, Object> metadata, List<String> includes, boolean taint, String source) {

  /** A metadata value, accepting both nested ({@code sonar: {type: x}}) and flat ({@code sonar-type: x}) keys. */
  public Object meta(String dottedKey) {
    Object nested = metadata;
    for (String part : dottedKey.split("\\.")) {
      if (!(nested instanceof Map<?, ?> map)) {
        nested = null;
        break;
      }
      nested = map.get(part);
    }
    if (nested != null) {
      return nested;
    }
    Object flat = metadata.get(dottedKey.replace('.', '-'));
    return flat != null ? flat : metadata.get(dottedKey.replace('.', '_'));
  }

  /** A metadata value as a list of strings, whether written as a scalar or a list. */
  public List<String> metaList(String dottedKey) {
    Object value = meta(dottedKey);
    if (value == null) {
      return List.of();
    }
    if (value instanceof List<?> list) {
      return list.stream().filter(item -> item != null).map(Object::toString).toList();
    }
    return List.of(value.toString());
  }

  /** A metadata value as a trimmed string, or empty. */
  public String metaString(String dottedKey) {
    Object value = meta(dottedKey);
    return value == null ? "" : value.toString().trim();
  }
}

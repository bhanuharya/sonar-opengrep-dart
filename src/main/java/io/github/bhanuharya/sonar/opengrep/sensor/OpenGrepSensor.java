package io.github.bhanuharya.sonar.opengrep.sensor;

import io.github.bhanuharya.sonar.opengrep.OpenGrepProperties;
import io.github.bhanuharya.sonar.opengrep.rules.RuleCatalog;
import io.github.bhanuharya.sonar.opengrep.rules.RuleMapper;
import io.github.bhanuharya.sonar.opengrep.rules.SdtRules;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.sonar.api.batch.fs.FileSystem;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.TextRange;
import org.sonar.api.batch.rule.ActiveRule;
import org.sonar.api.batch.rule.Severity;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.batch.sensor.issue.NewExternalIssue;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.rule.RuleKey;
import org.sonar.api.rules.RuleType;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

/**
 * Imports OpenGrep results. A result lands on the native OpenGrep rule for its file's
 * language when that rule is active in the project's profile — so hotspot rules become
 * real Security Hotspots — and otherwise, if allowed, as an external issue. Every result
 * is accounted for in the log: imported, external, or skipped with the reason.
 */
public class OpenGrepSensor implements Sensor {

  private static final Logger LOG = Loggers.get(OpenGrepSensor.class);
  static final String ENGINE_ID = "opengrep";
  private static final int MAX_MESSAGE = 4000;

  @Override
  public void describe(SensorDescriptor descriptor) {
    descriptor.name("OpenGrep report import").onlyWhenConfiguration(
      config -> config.getStringArray(OpenGrepProperties.REPORT_PATHS).length > 0);
  }

  @Override
  public void execute(SensorContext context) {
    boolean fallback = context.config().getBoolean(OpenGrepProperties.EXTERNAL_FALLBACK).orElse(true);
    Counts counts = new Counts();
    Set<String> seen = new HashSet<>();
    for (String reportPath : context.config().getStringArray(OpenGrepProperties.REPORT_PATHS)) {
      Path report = resolve(context.fileSystem(), reportPath.trim());
      List<ReportFinding> findings;
      try {
        findings = ReportParser.parse(report);
      } catch (IOException e) {
        LOG.error("OpenGrep: cannot import {}: {}", report, e.getMessage());
        continue;
      }
      LOG.info("OpenGrep: importing {} results from {}", findings.size(), report);
      for (ReportFinding finding : findings) {
        importFinding(context, finding, fallback, counts, seen);
      }
    }
    counts.log();
  }

  private static Path resolve(FileSystem fs, String path) {
    Path candidate = Path.of(path);
    return candidate.isAbsolute() ? candidate : fs.baseDir().toPath().resolve(candidate);
  }

  private static void importFinding(SensorContext context, ReportFinding finding, boolean fallback,
    Counts counts, Set<String> seen) {
    FileSystem fs = context.fileSystem();
    InputFile file = finding.path().isEmpty() ? null : fs.inputFile(fs.predicates().hasPath(finding.path()));
    String dedupe = finding.kind() + "\u0000" + finding.ruleId() + '\u0000' + finding.path() + '\u0000'
      + finding.startLine() + '\u0000' + finding.message() + '\u0000' + finding.commit()
      + '\u0000' + finding.dependency();
    if (!seen.add(dedupe)) {
      counts.skip("duplicate result");
      return;
    }
    switch (finding.kind()) {
      case SECRET:
        importSecret(context, finding, file, counts);
        return;
      case DEPENDENCY:
        importDependency(context, finding, file, counts);
        return;
      default:
        break;
    }
    if (file == null) {
      counts.skip("file not indexed by SonarQube");
      return;
    }
    RuleKey ruleKey = file.language() == null ? null : activeRule(context, file.language(), finding.ruleId());
    if (ruleKey != null) {
      NewIssue issue = context.newIssue().forRule(ruleKey);
      issue.at(location(issue.newLocation(), file, finding)).save();
      counts.imported++;
      return;
    }
    if (!fallback) {
      counts.skip("no active OpenGrep rule for " + (file.language() == null ? "files without a language" : file.language()));
      return;
    }
    NewExternalIssue external = context.newExternalIssue()
      .engineId(ENGINE_ID)
      .ruleId(finding.ruleId().isEmpty() ? "unknown" : finding.ruleId())
      .type(finding.security() ? RuleType.VULNERABILITY : RuleType.CODE_SMELL)
      .severity(Severity.valueOf(RuleMapper.severity(finding.severity())));
    external.at(location(external.newLocation(), file, finding)).save();
    counts.external++;
  }

  /**
   * A secret in a file of the checkout sits on its line; one found only in git history
   * (the file or line is gone) is raised on the project, because it is still leaked.
   */
  private static void importSecret(SensorContext context, ReportFinding finding, InputFile file, Counts counts) {
    String kind = finding.ruleId().isEmpty() ? "secret" : finding.ruleId();
    String commit = finding.commit().length() > 12 ? finding.commit().substring(0, 12) : finding.commit();
    boolean inCheckout = file != null && finding.startLine() >= 1 && finding.startLine() <= file.lines();
    if (inCheckout) {
      String message = "Committed secret (" + kind + "). Rotate it, then load it from a secret store.";
      saveSdtIssue(context, SdtRules.SECRET, file, finding.startLine(), finding.endLine(), message, null, counts);
      return;
    }
    String message = "Secret (" + kind + ") in git history: " + (finding.path().isEmpty() ? "unknown file" : finding.path())
      + (finding.startLine() > 0 ? ":" + finding.startLine() : "") + (commit.isEmpty() ? "" : " at commit " + commit)
      + ". It is not in the current checkout but every clone still has it: rotate it.";
    saveSdtIssue(context, SdtRules.SECRET_IN_HISTORY, null, 0, 0, message, null, counts);
  }

  /**
   * A vulnerable dependency sits on the line of its lockfile/manifest that names the
   * package (or the whole file, or the project when the file is not indexed). One no
   * source file imports is a Security Hotspot rather than a Vulnerability.
   */
  private static void importDependency(SensorContext context, ReportFinding finding, InputFile file, Counts counts) {
    ReportFinding.Dependency dep = finding.dependency();
    String advisory = finding.ruleId().isEmpty() ? "A known vulnerability" : finding.ruleId();
    String message = advisory + " in " + dep.name() + " " + dep.installed()
      + (dep.fixed().isEmpty() ? " (no fixed version published yet)" : ": upgrade to " + dep.fixed())
      + (dep.unreachable() ? ". No source file imports this package: confirm it is not loaded at runtime." : ".")
      + (file == null && !finding.path().isEmpty() ? " Declared in " + finding.path() + "." : "");
    String rule = dep.unreachable() ? SdtRules.UNREACHABLE_DEPENDENCY : SdtRules.VULNERABLE_DEPENDENCY;
    int line = file == null ? 0 : Math.max(finding.startLine(), lineMentioning(file, dep.name()));
    String severity = dep.unreachable() ? null : RuleMapper.severity(finding.severity());
    saveSdtIssue(context, rule, file, line, line, message, severity, counts);
  }

  private static void saveSdtIssue(SensorContext context, String ruleKey, InputFile file, int startLine, int endLine,
    String message, String severity, Counts counts) {
    RuleKey key = RuleKey.of(SdtRules.REPOSITORY, ruleKey);
    if (context.activeRules().find(key) == null) {
      counts.skip("SDT rule " + ruleKey + " not active (activate the sdt repository in the secrets profile)");
      return;
    }
    NewIssue issue = context.newIssue().forRule(key);
    if (severity != null) {
      issue.overrideSeverity(Severity.valueOf(severity));
    }
    NewIssueLocation location = issue.newLocation().message(truncate(message));
    if (file == null) {
      location.on(context.project());
      counts.projectLevel++;
    } else {
      location.on(file);
      TextRange range = range(file, startLine, endLine);
      if (range != null) {
        location.at(range);
      }
    }
    issue.at(location).save();
    counts.imported++;
  }

  /** The first line of a manifest or lockfile that names the package, or 0. */
  static int lineMentioning(InputFile file, String name) {
    if (name == null || name.isEmpty()) {
      return 0;
    }
    try {
      String[] lines = file.contents().split("\r?\n", -1);
      for (int i = 0; i < lines.length; i++) {
        String line = lines[i];
        if (line.contains("\"" + name + "\"") || line.contains("'" + name + "'")
          || line.contains("/" + name + "\"") || line.trim().startsWith(name + ":")) {
          return i + 1;
        }
      }
    } catch (IOException | RuntimeException e) {
      return 0;
    }
    return 0;
  }

  private static String truncate(String message) {
    return message.length() > MAX_MESSAGE ? message.substring(0, MAX_MESSAGE - 1) + "…" : message;
  }

  /**
   * The active OpenGrep rule a result belongs to. OpenGrep prefixes rule ids with the
   * config directory ("rules.dart.my-rule" for rule "my-rule"), so a suffix match on a
   * dot boundary is accepted when the exact id is not active.
   */
  static RuleKey activeRule(SensorContext context, String language, String ruleId) {
    String repository = RuleCatalog.repositoryKey(language);
    RuleKey exact = RuleKey.of(repository, ruleId);
    if (context.activeRules().find(exact) != null) {
      return exact;
    }
    RuleKey best = null;
    for (ActiveRule active : context.activeRules().findByRepository(repository)) {
      String id = active.ruleKey().rule();
      if (ruleId.endsWith("." + id) && (best == null || id.length() > best.rule().length())) {
        best = active.ruleKey();
      }
    }
    return best;
  }

  private static NewIssueLocation location(NewIssueLocation location, InputFile file, ReportFinding finding) {
    location.on(file);
    TextRange range = range(file, finding.startLine(), finding.endLine());
    if (range != null) {
      location.at(range);
    }
    String message = finding.message().isBlank() ? finding.ruleId() : finding.message().strip();
    return location.message(truncate(message));
  }

  /** The reported lines, clamped to the file; null (a file-level issue) when there is no usable line. */
  static TextRange range(InputFile file, int startLine, int endLine) {
    int lines = file.lines();
    if (startLine < 1 || lines < 1) {
      return null;
    }
    int start = Math.min(startLine, lines);
    int end = Math.min(Math.max(endLine, start), lines);
    try {
      return end == start ? file.selectLine(start) : file.newRange(start, 0, end, file.selectLine(end).end().lineOffset());
    } catch (IllegalArgumentException emptyLine) {
      // Sonar refuses a zero-width range, which is what an empty line selects.
      try {
        return file.selectLine(start);
      } catch (IllegalArgumentException alsoEmpty) {
        return null;
      }
    }
  }

  private static final class Counts {
    int imported;
    int projectLevel;
    int external;
    final Map<String, Integer> skipped = new TreeMap<>();

    void skip(String reason) {
      skipped.merge(reason, 1, Integer::sum);
    }

    void log() {
      LOG.info("OpenGrep: {} imported on native rules ({} on the project), {} as external issues, {} skipped",
        imported, projectLevel, external, skipped.values().stream().mapToInt(Integer::intValue).sum());
      skipped.forEach((reason, count) -> LOG.info("OpenGrep:   skipped {}: {}", count, reason.toLowerCase(Locale.ROOT)));
    }
  }
}

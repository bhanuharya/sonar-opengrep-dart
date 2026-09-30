package io.github.bhanuharya.sonar.opengrep.sensor;

import io.github.bhanuharya.sonar.opengrep.OpenGrepProperties;
import io.github.bhanuharya.sonar.opengrep.rules.RuleCatalog;
import io.github.bhanuharya.sonar.opengrep.rules.RuleMapper;
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
    if (file == null) {
      counts.skip("file not indexed by SonarQube");
      return;
    }
    if (!seen.add(finding.ruleId() + '\u0000' + file.uri() + '\u0000' + finding.startLine() + '\u0000' + finding.message())) {
      counts.skip("duplicate result");
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
    return location.message(message.length() > MAX_MESSAGE ? message.substring(0, MAX_MESSAGE - 1) + "…" : message);
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
    int external;
    final Map<String, Integer> skipped = new TreeMap<>();

    void skip(String reason) {
      skipped.merge(reason, 1, Integer::sum);
    }

    void log() {
      LOG.info("OpenGrep: {} imported on OpenGrep rules, {} as external issues, {} skipped",
        imported, external, skipped.values().stream().mapToInt(Integer::intValue).sum());
      skipped.forEach((reason, count) -> LOG.info("OpenGrep:   skipped {}: {}", count, reason.toLowerCase(Locale.ROOT)));
    }
  }
}

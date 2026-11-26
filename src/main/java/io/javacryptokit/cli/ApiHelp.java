package io.javacryptokit.cli;

import io.javacryptokit.i18n.Messages;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

/** Queries for the API command registry. Example lines stay copyable. */
final class ApiHelp {
    private ApiHelp() { }

    static int show(String path, CliCommands.Spec spec, boolean examples, PrintStream out, Path runningJar) throws CryptoCli.CliException {
        if (spec != null) {
            if (examples) {
                String commandJar = CliHelp.examplePrelude(out, runningJar);
                printExample(spec.topic, out, commandJar);
            } else command(spec, out);
            return 0;
        }
        if (path.equals("api")) {
            if (examples) CliHelp.examplePrelude(out, runningJar);
            out.println(Messages.get(examples ? "api.help.exampleIndex" : "api.help.overview"));
            for (ApiCommands.Purpose purpose : ApiCommands.Purpose.values()) {
                out.println(Messages.get("api.help.purpose." + purpose.name()));
                for (String group : ApiCommands.groups(purpose)) {
                    String command = "api " + group;
                    if (examples) {
                        out.println("  " + command + " --examples");
                    } else {
                        CliCommands.Spec leaf = CliCommands.find(command);
                        row(out, command + " --help", leaf == null ? Messages.get("api.help.group." + group) : summary(leaf), 28);
                    }
                }
            }
            if (!examples) out.println(Messages.get("api.help.groupHint"));
            return 0;
        }
        List<CliCommands.Spec> children = new ArrayList<>();
        for (CliCommands.Spec child : ApiCommands.ALL) {
            if (child.name.startsWith(path + " ")) children.add(child);
        }
        if (children.isEmpty()) throw ApiInput.problem("api.err.command");
        if (examples) {
            String commandJar = CliHelp.examplePrelude(out, runningJar);
            String flow = "api.flow." + path.substring(4);
            if (Messages.has(Messages.current(), flow)) printExampleText(Messages.get(flow), out, commandJar);
            else for (CliCommands.Spec child : children) printExample(child.topic, out, commandJar);
        } else {
            out.println(path);
            printAlias(path, out);
            for (CliCommands.Spec child : children) {
                row(out, child.name + " --help", summary(child), 33);
            }
            out.println("  " + path + " --examples");
        }
        return 0;
    }

    private static String summary(CliCommands.Spec spec) {
        return Messages.get("api.summary." + spec.topic);
    }

    private static void command(CliCommands.Spec spec, PrintStream out) {
        out.println(spec.name + " — " + summary(spec));
        printAlias(spec.name, out);
        out.println(Messages.get(spec.access == CliCommands.Access.ADMIN ? "api.help.admin" : "api.help.open"));
        out.println(Messages.get("api.details." + spec.topic));
        out.println();

        Map<String, List<String>> sections = new LinkedHashMap<>();
        boolean grouped = spec.name.startsWith("api aes ") || spec.name.startsWith("api jwt ") || spec.name.startsWith("api oauth ");
        for (String option : spec.options()) {
            String section = grouped ? section(option) : "options";
            sections.computeIfAbsent(section, name -> new ArrayList<>()).add(option);
        }
        for (Map.Entry<String, List<String>> section : sections.entrySet()) {
            out.println(Messages.get("api.help." + section.getKey()));
            for (String option : section.getValue()) {
                String alias = CliCommands.optionAlias(spec, option);
                String label = option + (alias == null ? "" : " (" + alias + ")")
                        + (spec.flags.contains(option) ? "" : " <value>");
                row(out, label, Messages.get("api.option." + option.substring(2)), 33);
            }
            out.println();
        }
        out.println("  --lang ko|en    --help / -h    --examples");
    }

    private static String section(String option) {
        switch (option) {
            case "--algorithm": case "--format": case "--type":
            case "--key-file": case "--key-encoding": case "--key-id": case "--kdf":
            case "--salt": case "--salt-file": case "--iterations": case "--pass-file":
            case "--private-key": case "--public-key": case "--jwks-file": case "--kid":
                return "section.keys";
            case "--issuer": case "--subject": case "--audience": case "--any-audience":
            case "--profile": case "--typ": case "--clock-skew": case "--at":
            case "--require-claims": case "--require-claim-values-file": case "--forbid-claim":
            case "--scope": case "--roles": case "--require-permission":
            case "--scope-claim": case "--roles-claim": case "--client-id-claim":
                return "section.policy";
            case "--out": case "--encoding": case "--show": case CliCommands.ADMIN_FILE:
                return "section.output";
            default:
                return "section.input";
        }
    }

    private static void printAlias(String path, PrintStream out) {
        String alias = CliCommands.commandAlias(path);
        if (alias != null) out.println(Messages.get("api.help.alias", alias));
    }

    private static void row(PrintStream out, String name, String description, int column) {
        String left = "  " + name;
        if (CliHelp.width(left) + 2 > column) {
            out.println(left);
            left = "";
        }
        String prefix = CliHelp.pad(left, column);
        StringBuilder line = new StringBuilder(prefix);
        for (String word : description.split("\\s+")) {
            if (line.length() > prefix.length() && CliHelp.width(line + " " + word) > 80) {
                out.println(line);
                line.setLength(0);
                line.append(CliHelp.pad("", column));
            }
            if (line.length() > prefix.length()) line.append(' ');
            line.append(word);
        }
        out.println(line);
    }

    private static void printExample(String topic, PrintStream out, String commandJar) {
        printExampleText(Messages.get("api.example." + topic), out, commandJar);
    }

    private static void printExampleText(String examples, PrintStream out, String commandJar) {
        String text = examples.replace("{jar}", commandJar);
        out.print(text.endsWith("\n") ? text : text + "\n");
    }
}

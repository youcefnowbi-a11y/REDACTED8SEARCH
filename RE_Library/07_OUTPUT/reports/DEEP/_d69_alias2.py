import os, re, collections

root = r"RE_Library\01_SOURCE_c2\metasploit"
core = os.path.join(root, "lib", "msf", "core")

RX_ALIAS = re.compile(
    r"""^\s*
        (?:alias_method\s*(?:\(\s*)?|alias\s+)
        (?::|['"])?([A-Za-z_$@][\w?!=]*)(?::|['"])?
        \s*(?:,\s*)?
        (?::|['"])?([A-Za-z_$@][\w?!=]*)(?::|['"])?
        \s*\)?\s*(?:\#.*)?$
    """,
    re.X,
)

real = []
for dp, ds, fs in os.walk(core):
    for f in fs:
        if not f.endswith(".rb"):
            continue
        p = os.path.join(dp, f)
        rel = os.path.relpath(p, core)
        for i, l in enumerate(open(p, encoding="utf-8", errors="ignore").read().split("\n"), 1):
            if not re.match(r"^\s*alias", l):
                continue
            m = RX_ALIAS.match(l)
            if m:
                real.append((rel, i, m.group(1), m.group(2)))

print("=== PROVING OR KILLING THE DEAD-ALIAS CLASS ===")
print("real alias statements: %d" % len(real))
print()

# Build the full corpus text once, for name-usage counting.
corpus = []
for dp, ds, fs in os.walk(root):
    if ".git" in dp:
        continue
    for f in fs:
        if f.endswith((".rb",)):
            corpus.append(open(os.path.join(dp, f), encoding="utf-8", errors="ignore").read())
BLOB = "\n".join(corpus)
print("corpus .rb files scanned: %d" % len(corpus))
print()

dead_targets = []
dead_aliases = []
for rel, i, new, old in real:
    # how often is the ALIAS name referenced anywhere?
    n_new = len(re.findall(r"(?<![\w:.])(?:\.|:)" + re.escape(new) + r"\b", BLOB))
    # how often is the TARGET name referenced (as a call/reference, not the alias line)?
    n_old = len(re.findall(r"(?<![\w:.])(?:\.|:)" + re.escape(old) + r"\b", BLOB))
    if n_new == 0:
        dead_aliases.append((rel, i, new, old))
    if n_old == 0:
        dead_targets.append((rel, i, new, old))

print("A) alias name NEVER referenced anywhere (dead alias): %d" % len(dead_aliases))
for rel, i, new, old in dead_aliases:
    print("      %s:%d  %s -> %s" % (rel, i, new, old))
print()
print("B) TARGET name never referenced anywhere (alias to an unused impl): %d" % len(dead_targets))
for rel, i, new, old in dead_targets:
    print("      %s:%d  %s -> %s" % (rel, i, new, old))
print()

# C) The shared-name caveat: if the target name is a common word, regex
#    over-counts. Print the most-referenced targets so the reader can see which
#    "0" results are trustworthy and which are small_sample artifacts.
print("C) reference counts for every alias pair:")
for rel, i, new, old in real:
    n_new = len(re.findall(r"(?<![\w:.])(?:\.|:)" + re.escape(new) + r"\b", BLOB))
    n_old = len(re.findall(r"(?<![\w:.])(?:\.|:)" + re.escape(old) + r"\b", BLOB))
    flag = "  <-- DEAD" if (n_new == 0 or n_old == 0) else ""
    print("   %-50s L%-5d %-26s new=%-4d old=%-4d%s" % (rel, i, "%s -> %s" % (new, old), n_new, n_old, flag))

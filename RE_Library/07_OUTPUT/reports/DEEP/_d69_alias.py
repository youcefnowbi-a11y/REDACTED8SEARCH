import os, re, collections

base = r"RE_Library\01_SOURCE_c2\metasploit\lib\msf\core"

# A REAL alias statement, Ruby grammar:
#   alias new_name old_name
#   alias :new_name :old_name
#   alias_method :new_name, :old_name
#   alias $new $old   /  alias_method 'new', 'old'
RX_ALIAS = re.compile(
    r"""^\s*
        (?:alias_method\s*(?:\(\s*)?|alias\s+)
        (?::|['"])?([A-Za-z_$@][\w?!=]*|[$\w]+)(?::|['"])?
        \s*(?:,\s*)?
        (?::|['"])?([A-Za-z_$@][\w?!=]*|[$\w]+)(?::|['"])?
        \s*\)?\s*$
    """,
    re.X,
)

real = []          # (relpath, line, form, newname, oldname)
prose = []         # (relpath, line, text)  -- ^\s*alias but NOT a statement
files_real = set()

for dp, ds, fs in os.walk(base):
    for f in fs:
        if not f.endswith(".rb"):
            continue
        p = os.path.join(dp, f)
        rel = os.path.relpath(p, base)
        lines = open(p, encoding="utf-8", errors="ignore").read().split("\n")
        for i, l in enumerate(lines, 1):
            if not re.match(r"^\s*alias", l):
                continue
            st = l.strip()
            m = RX_ALIAS.match(l)
            if m:
                form = "alias_method" if st.startswith("alias_method") else "alias"
                real.append((rel, i, form, m.group(1), m.group(2)))
                files_real.add(rel)
            else:
                prose.append((rel, i, st))

print("=== REAL alias statements: %d in %d files ===" % (len(real), len(files_real)))
c = collections.Counter(r[2] for r in real)
for k, v in c.items():
    print("   %-14s %d" % (k, v))

print()
print("=== ^\\s*alias lines that are NOT statements (prose/comments): %d ===" % len(prose))
for rel, i, st in prose[:30]:
    print("   %-52s L%-5d %s" % (rel, i, st[:80]))

print()
print("=== real aliases, name vs target ===")
kinds = collections.Counter()
same = []
for rel, i, form, new, old in real:
    if new == old:
        kinds["SAME-NAME (no-op)"] += 1
        same.append((rel, i, new, old))
    else:
        kinds["distinct"] += 1
for k, v in kinds.items():
    print("   %-20s %d" % (k, v))
print()
for rel, i, new, old in same:
    print("   SAME %s:%d  %s -> %s" % (rel, i, new, old))

print()
print("=== first 30 real aliases ===")
for rel, i, form, new, old in real[:30]:
    print("   %-50s L%-5d %-12s %-26s -> %s" % (rel, i, form, new, old))

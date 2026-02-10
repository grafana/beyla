#!/usr/bin/env python3
"""Split docker.Build in OBI k8s tests: OBI components need .obi-src context, Beyla needs repo root."""
import re
import sys

def main():
    if len(sys.argv) < 2:
        return 1
    path = sys.argv[1]
    with open(path) as f:
        content = f.read()

    # Match the full docker.Build block
    pat = (
        r"(\tif err := docker\.Build\(os\.Stdout, )tools\.ProjectDir\(\)(,\s*\n)"
        r"((?:\s*docker\.ImageBuild\{[^}]+\},?\s*\n)+)"
        r"(\t\);\s*err != nil \{\s*\n\s*slog\.Error\(\"can't build docker images\", \"error\", err\)\s*\n\s*os\.Exit\(-1\)\s*\n\s*\})"
    )
    m = re.search(pat, content)
    if not m:
        return 0

    obi, beyla = [], []
    for line in m.group(3).split('\n'):
        line = line.rstrip()
        if not line.strip():
            continue
        # Preserve indentation; ensure trailing comma
        line = line.rstrip(',') + ','
        # Beyla Dockerfiles must build from repo root because they COPY vendor/.
        # This includes pre-transform (DockerfileOBI, DockerfileK8sCache) and post-transform
        # (DockerfileBeyla, DockerfileBeylaK8sCache) names. Split runs before behavioral
        # transforms, so we must match DockerfileOBI here.
        if (
            'DockerfileOBI' in line
            or 'DockerfileBeyla' in line
            or 'DockerfileK8sCache' in line
            or 'DockerfileBeylaK8sCache' in line
        ):
            beyla.append(line)
        else:
            obi.append(line)

    new_block = '\troot := tools.ProjectDir()\n\tobiRoot := path.Join(root, ".obi-src")\n'
    if obi:
        new_block += '\tif err := docker.Build(os.Stdout, obiRoot,\n'
        new_block += '\n'.join(obi) + '\n'
        new_block += '\t); err != nil {\n\t\tslog.Error("can\'t build OBI docker images", "error", err)\n\t\tos.Exit(-1)\n\t}\n'
    if beyla:
        new_block += '\tif err := docker.Build(os.Stdout, root,\n'
        new_block += '\n'.join(beyla) + '\n'
        new_block += '\t); err != nil {\n\t\tslog.Error("can\'t build Beyla docker image", "error", err)\n\t\tos.Exit(-1)\n\t}\n'

    new_content = content[:m.start()] + new_block + content[m.end():]

    if '"path"' not in new_content:
        new_content = new_content.replace('\t"os"', '\t"path"\n\t"os"')

    with open(path, 'w') as f:
        f.write(new_content)
    return 0

if __name__ == '__main__':
    sys.exit(main())

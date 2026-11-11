"""Fail on a workflow dependency that is not pinned: python3 .github/tests/action-pins.py.

A tag can be repointed by whoever controls the action's repository, so every
third-party action is referenced by commit SHA and every container image by
digest. The trailing version comment is what upgrade tooling and vulnerability
scans read, so it must be a full version.

This catches a pin that drifts back in an ordinary edit. It reads workflow
files line by line, so a dependency written in a form it cannot read is
reported rather than skipped.
"""
from pathlib import Path
import re
import unittest

GITHUB = Path(__file__).resolve().parents[1]

DEPENDENCY = r'(uses|image|container)'
# A dependency key where YAML puts keys: at the start of a line or list item.
# Quotes and a space before the colon are valid YAML, so they are detected too.
KEY = re.compile(rf'''^\s*(?:-\s+)?['"]?{DEPENDENCY}['"]?\s*:''')
# The same key inside a flow mapping: `- { uses: ... }`, `postgres: { image: ... }`.
FLOW = re.compile(r'''^\s*(?:-\s+)?(?:['"]?[\w.-]+['"]?\s*:\s*)?\{''')
FLOW_KEY = re.compile(rf'''[{{,]\s*['"]?{DEPENDENCY}['"]?\s*:''')
# `? key` on one line and `: value` on the next is the same mapping to YAML.
EXPLICIT_KEY = re.compile(r'^\s*(?:-\s+)?\?(?:\s|$)')
# `key: |` or `key: >` starts a block scalar. Its lines are text, not keys.
BLOCK_SCALAR = re.compile(r'^(\s*(?:-\s+)?)[^\s#][^#]*:\s*[|>][+-]?\d*[+-]?\s*(?:#.*)?$')

USES = re.compile(r'^\s*(?:-\s+)?uses:\s+(\S+)(?:\s+#\s*(.*))?$')
IMAGE = re.compile(r'^\s*(?:-\s+)?(?:image|container):\s+(\S+)(?:\s+#.*)?$')
# `container:` with nothing after it opens a mapping whose `image:` is checked.
CONTAINER_MAPPING = re.compile(r'^\s*container:\s*(?:#.*)?$')

PINNED_ACTION = re.compile(r'^[\w.-]+/[\w./-]+@[0-9a-f]{40}$')
FULL_VERSION = re.compile(r'^v?\d+\.\d+\.\d+$')
DIGEST = re.compile(r'@sha256:[0-9a-f]{64}$')


def is_local_dockerfile(ref):
    """A Docker action built from this repository, not pulled from a registry."""
    name = ref.rsplit('/', 1)[-1]
    return name == 'Dockerfile' or name.startswith('Dockerfile.') or name.endswith('.Dockerfile')


def dependency_key(line):
    """The dependency key this line declares, or None."""
    key = KEY.match(line)
    if key:
        return key.group(1)
    if FLOW.match(line):
        key = FLOW_KEY.search(line)
        if key:
            return key.group(1)
    return None


def violations(text):
    """One message per unpinned or unreadable dependency in a workflow file."""
    found = []
    block_indent = None
    for number, line in enumerate(text.splitlines(), 1):
        indent = len(line) - len(line.lstrip())
        if block_indent is not None:
            if not line.strip() or indent > block_indent:
                continue
            block_indent = None
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        block = BLOCK_SCALAR.match(line)
        if block:
            block_indent = len(block.group(1))
        if EXPLICIT_KEY.match(line):
            found.append(f'{number}: write the key and its value on one line so it can be checked')
            continue
        key = dependency_key(line)
        if not key or CONTAINER_MAPPING.match(line):
            continue
        uses = USES.match(line)
        if uses:
            ref, comment = uses.group(1).strip('\'"'), uses.group(2)
            if ref.startswith('./'):
                continue
            if ref.startswith('docker://'):
                if not DIGEST.search(ref):
                    found.append(f'{number}: {ref} is not pinned to a digest')
            elif not PINNED_ACTION.match(ref):
                found.append(f'{number}: {ref} is not pinned to a commit SHA')
            elif not FULL_VERSION.match(comment or ''):
                found.append(f'{number}: {ref} needs a full version comment, e.g. "# v4.2.2"')
            continue
        image = IMAGE.match(line)
        if not image:
            found.append(f'{number}: write `{key}:` as a plain `{key}: <value>` line so it can be checked')
            continue
        ref = image.group(1).strip('\'"')
        if not is_local_dockerfile(ref) and not DIGEST.search(ref):
            found.append(f'{number}: image {ref} is not pinned to a digest')
    return found


def workflow_files():
    """Workflows, plus the metadata of any action defined in this repository."""
    files = [p for p in (GITHUB / 'workflows').glob('*') if p.suffix in ('.yml', '.yaml')]
    files += [p for p in (GITHUB / 'actions').rglob('*') if p.name in ('action.yml', 'action.yaml')]
    return sorted(files)


SHA = 'a' * 40
DIGEST_REF = 'sha256:' + 'b' * 64


class Violations(unittest.TestCase):
    def test_accepts_pinned_references(self):
        text = '\n'.join([
            f'      - uses: actions/checkout@{SHA} # v4.2.2',
            f'        uses: owner/repo/path@{SHA} # 1.0.0',
            '        uses: ./.github/workflows/lint.yml',
            '      - uses: ./.github/actions/aws-stage',
            f'      - uses: docker://alpine@{DIGEST_REF}',
            f'        image: pgvector/pgvector:0.8.7-pg16@{DIGEST_REF}',
            f'    container: node:22@{DIGEST_REF}',
            '    container:',
            f'      image: node:22@{DIGEST_REF}',
        ])
        self.assertEqual(violations(text), [])

    def test_rejects_a_tag_or_branch(self):
        for ref in ('actions/checkout@v4', 'actions/checkout@v4.2.2', 'actions/checkout@main', 'actions/checkout'):
            with self.subTest(ref=ref):
                self.assertEqual(len(violations(f'      - uses: {ref}')), 1)

    def test_rejects_a_short_sha(self):
        self.assertEqual(len(violations('      - uses: actions/checkout@abc1234 # v4.2.2')), 1)

    def test_rejects_a_missing_or_partial_version_comment(self):
        for comment in ('', ' # v4', ' # v4.2', ' # latest'):
            with self.subTest(comment=comment):
                self.assertEqual(len(violations(f'      - uses: actions/checkout@{SHA}{comment}')), 1)

    def test_rejects_an_image_without_a_digest(self):
        for line in (
            '        image: pgvector/pgvector:pg16',
            '      - uses: docker://alpine:3.20',
            '    container: node:22',
            '    container: ${{ matrix.container }}',
            '  image: docker://alpine:3.20',
        ):
            with self.subTest(line=line):
                self.assertEqual(len(violations(line)), 1)

    def test_accepts_a_local_dockerfile(self):
        for ref in ('Dockerfile', './docker/build.Dockerfile', 'docker/Dockerfile.ci'):
            with self.subTest(ref=ref):
                self.assertEqual(violations(f'  image: {ref}'), [])

    def test_rejects_a_spelling_it_cannot_check(self):
        for line in (
            '      - uses : actions/checkout@v4',
            "      - 'uses': actions/checkout@v4",
            '      - "uses": actions/checkout@v4',
            '      - { uses: actions/checkout@v4 }',
            '      - { name: Checkout, uses: actions/checkout@v4 }',
            '      - uses: >-',
            '        image : pgvector/pgvector:pg16',
            "        'image': pgvector/pgvector:pg16",
            '      postgres: { image: pgvector/pgvector:pg16 }',
            '    container: { image: node:22 }',
            "    'container': node:22",
            '      - ? uses',
            '        ? image',
        ):
            with self.subTest(line=line):
                self.assertEqual(len(violations(line)), 1)

    def test_ignores_text_that_is_not_a_key(self):
        text = '\n'.join([
            '      # uses: actions/checkout@v4',
            '    # image: pgvector/pgvector:pg16',
            '          docker_image: example',
            '        run: echo "image: node:18 uses: nothing"',
            '      - run: |',
            '          echo "building"',
            '          image: node:18',
            '',
            '          uses: generated-value',
            '          cat <<EOF',
            '          - { uses: actions/checkout@v4 }',
            '          ? uses',
            '          EOF',
            '        description: >-',
            '          container: node:18',
        ])
        self.assertEqual(violations(text), [])

    def test_checks_the_key_after_a_block_scalar_ends(self):
        text = '\n'.join([
            '      - run: |',
            '          uses: generated-value',
            '      - uses: actions/checkout@v4',
        ])
        self.assertEqual(violations(text), ['3: actions/checkout@v4 is not pinned to a commit SHA'])

    def test_reports_the_line_number(self):
        self.assertTrue(violations('name: CI\n\n      - uses: actions/checkout@v4')[0].startswith('3: '))


class Repository(unittest.TestCase):
    def test_every_workflow_dependency_is_pinned(self):
        files = workflow_files()
        self.assertTrue(files)
        found = [
            f'{path.relative_to(GITHUB.parent)}:{message}'
            for path in files
            for message in violations(path.read_text())
        ]
        self.assertEqual(found, [], '\n' + '\n'.join(found))


if __name__ == '__main__':
    unittest.main()

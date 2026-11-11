"""Fail on a workflow dependency that is not pinned: python3 .github/tests/action-pins.py.

A tag can be repointed by whoever controls the action's repository, so every
third-party action is referenced by commit SHA and every container image by
digest. The trailing version comment is what upgrade tooling and vulnerability
scans read, so it must be a full version.
"""
from pathlib import Path
import re
import unittest

GITHUB = Path(__file__).resolve().parents[1]

USES = re.compile(r'^\s*(?:-\s*)?uses:\s*(\S+)(?:\s+#\s*(.*))?$')
IMAGE = re.compile(r'^\s*(?:-\s*)?image:\s*(\S+)')
PINNED_ACTION = re.compile(r'^[\w.-]+/[\w./-]+@[0-9a-f]{40}$')
FULL_VERSION = re.compile(r'^v?\d+\.\d+\.\d+$')
DIGEST = re.compile(r'@sha256:[0-9a-f]{64}$')


def violations(text):
    """One message per unpinned `uses:` or `image:` line in a workflow file."""
    found = []
    for number, line in enumerate(text.splitlines(), 1):
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
        if image and not DIGEST.search(image.group(1).strip('\'"')):
            found.append(f'{number}: image {image.group(1)} is not pinned to a digest')
    return found


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
        self.assertEqual(len(violations('        image: pgvector/pgvector:pg16')), 1)
        self.assertEqual(len(violations('      - uses: docker://alpine:3.20')), 1)

    def test_reports_the_line_number(self):
        self.assertTrue(violations('name: CI\n\n      - uses: actions/checkout@v4')[0].startswith('3: '))


class Repository(unittest.TestCase):
    def test_every_workflow_dependency_is_pinned(self):
        files = sorted(p for p in GITHUB.rglob('*') if p.suffix in ('.yml', '.yaml'))
        self.assertTrue(files)
        found = [
            f'{path.relative_to(GITHUB.parent)}:{message}'
            for path in files
            for message in violations(path.read_text())
        ]
        self.assertEqual(found, [], '\n' + '\n'.join(found))


if __name__ == '__main__':
    unittest.main()

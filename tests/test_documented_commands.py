"""Copyable commands in README.md and the deployer's printed next steps.

GitHub puts a copy button on every fenced block, and a pasted multi-line
PowerShell block runs on one Enter. A block that holds a -WhatIf preview and the
command it previews, or a deployer run without and with the switch that enables
the rules, would change Azure before the reader has read the preview. The
deployer's own instructions (its help examples, its Python check and the
cleanup it prints) follow the same commands.
"""
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / 'README.md'
DEPLOY_SCRIPT = ROOT / 'scripts' / 'Deploy-Lab.ps1'
REQUIREMENTS = ROOT / 'scripts' / 'requirements.txt'

# The sender setup shared by the README, the deployer's step 6 and the companion
# site. Off Windows the interpreter is python3. On Windows python3 can be the
# Microsoft Store alias, so the py launcher is preferred, then python. Debian,
# Ubuntu and Homebrew Python refuse a global pip install (PEP 668), so every step
# uses the interpreter of a virtual environment beside the checkout.
PYTHON_CHOICE = "$sysPy = if (-not $IsWindows) { 'python3' } elseif (Get-Command py -ErrorAction SilentlyContinue) { 'py' } else { 'python' }"
CREATE_VENV = "& $sysPy -m venv ../ccf-sender-venv"
INSTALL_DEPENDENCIES = "& $py -m pip install --require-hashes -r ./scripts/requirements.txt"
RUN_TESTS = "& $py -m unittest discover -s ./tests -v"
RUN_SENDER = "& $py ./scripts/Send-ThreatIntel.py"
STAGE_FAILURES = (
    ('venv', 'Creating the sender virtual environment failed.'),
    ('pip', 'Installing sender dependencies failed.'),
    ('tests', 'Sender offline tests failed; ingestion was not attempted.'),
    ('sender', 'Threat-intelligence ingestion failed.'),
)
SENDER_SETUP = (
    "$ErrorActionPreference = 'Stop'",
    PYTHON_CHOICE,
    CREATE_VENV,
    f"if ($LASTEXITCODE -ne 0) {{ throw '{STAGE_FAILURES[0][1]}' }}",
    "$py = if ($IsWindows) { '../ccf-sender-venv/Scripts/python.exe' } else { '../ccf-sender-venv/bin/python' }",
    INSTALL_DEPENDENCIES,
    f"if ($LASTEXITCODE -ne 0) {{ throw '{STAGE_FAILURES[1][1]}' }}",
    RUN_TESTS,
    f"if ($LASTEXITCODE -ne 0) {{ throw '{STAGE_FAILURES[2][1]}' }}",
    RUN_SENDER,
    f"if ($LASTEXITCODE -ne 0) {{ throw '{STAGE_FAILURES[3][1]}' }}",
)
WHATIF = re.compile(r'\s-WhatIf\b', re.IGNORECASE)
DEPLOYER_RUN = re.compile(r'^(?:pwsh (?:-\w+ )*|& ?)?\S*\bDeploy-Lab\.ps1\b')
ENABLE_SWITCH = re.compile(r'\s-Enable(?:Sentinel)?Rules\b', re.IGNORECASE)
BARE_PYTHON = re.compile(r'^(?:sudo )?(?:python3?|py|pip3?)(?:\.exe)?(?: |$)', re.IGNORECASE)
PIP_INSTALL = re.compile(r'\bpip3?(?:\.exe)? install\b', re.IGNORECASE)


def command_lines(text):
    """Join ` and \\ continuations, collapse spacing, drop comments and blank lines."""
    joined = re.sub(r'[`\\]\n\s*', ' ', text.replace('\r\n', '\n'))
    lines = (re.sub(r'\s+', ' ', line).strip() for line in joined.split('\n'))
    return [line for line in lines if line and not line.startswith('#')]


def fenced_blocks():
    """Return (location, commands) for each fenced block, as the site's scanner reads them."""
    source = README.read_text(encoding='utf-8').replace('\r\n', '\n')
    return [(f'README.md:{source.count(chr(10), 0, match.start()) + 1}', command_lines(match.group(1)))
            for match in re.finditer(r'^```[^\n]*\n(.*?)^```', source, re.MULTILINE | re.DOTALL)]


def without_whatif(command):
    return re.sub(r'\s+-WhatIf\b', '', command, count=1, flags=re.IGNORECASE)


def readme_sender_setup(test):
    """The README's own sender commands, in order, from the one block that runs the sender."""
    blocks = [(where, commands) for where, commands in fenced_blocks() if RUN_SENDER in commands]
    test.assertEqual(len(blocks), 1, 'exactly one README block runs the sender with the venv interpreter')
    where, commands = blocks[0]
    test.assertIn(SENDER_SETUP[0], commands, f'{where}: the block does not choose the interpreter')
    start = commands.index(SENDER_SETUP[0])
    return where, tuple(commands[start:start + len(SENDER_SETUP)])


def run_pwsh(script, **env):
    return subprocess.run(['pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
                          env={**os.environ, **env}, capture_output=True, text=True, check=False, timeout=600)


def write_fake_command(directory, name, exit_code, text):
    """A stand-in interpreter on PATH that prints text and exits with exit_code."""
    if os.name == 'nt':
        stream = ' 1>&2' if exit_code else ''
        (directory / f'{name}.cmd').write_text(f'@echo off\r\necho {text}{stream}\r\nexit /b {exit_code}\r\n',
                                               encoding='ascii')
    else:
        stream = ' >&2' if exit_code else ''
        path = directory / name
        path.write_text(f"#!/bin/sh\necho '{text}'{stream}\nexit {exit_code}\n", encoding='ascii')
        path.chmod(0o755)


class ReadmeCommandBlockTests(unittest.TestCase):
    def test_no_block_previews_a_command_with_whatif_and_also_runs_it(self):
        previews = cleanups = 0
        for where, commands in fenced_blocks():
            for command in filter(WHATIF.search, commands):
                previews += 1
                cleanups += bool(re.search(r'\s-Destroy\b', command))
                real = without_whatif(command)
                self.assertNotIn(real, commands, f'{where}: one block previews and then runs {real}')
        self.assertGreaterEqual(previews, 2, 'the deployment and the cleanup previews were checked')
        self.assertGreaterEqual(cleanups, 1)

    def test_each_whatif_preview_is_alone_and_a_later_block_runs_it(self):
        blocks = fenced_blocks()
        for index, (where, commands) in enumerate(blocks):
            previews = [command for command in commands if WHATIF.search(command)]
            if not previews:
                continue
            self.assertEqual(previews, commands, f'{where}: a -WhatIf preview shares its block with another command')
            for preview in previews:
                real = without_whatif(preview)
                self.assertTrue(any(real in later for _, later in blocks[index + 1:]),
                                f'{where}: no later block runs {real}')

    def test_no_block_runs_the_deployer_without_and_with_an_enable_switch(self):
        enables = 0
        for where, commands in fenced_blocks():
            runs = [command for command in commands if DEPLOYER_RUN.search(command)]
            enabling = [command for command in runs if ENABLE_SWITCH.search(command)]
            enables += len(enabling)
            self.assertTrue(not enabling or len(enabling) == len(runs),
                            f'{where}: one block runs Deploy-Lab.ps1 without -EnableSentinelRules and also runs '
                            f'{enabling[0] if enabling else ""}')
        self.assertGreaterEqual(enables, 1, 'the rule-enablement run was checked')

    def test_each_deployer_run_has_its_own_block(self):
        # The preview, the deployment, the rule enablement, the cleanup preview and
        # the cleanup each change something different, so each waits for its own copy.
        runs = 0
        for where, commands in fenced_blocks():
            deployer = [command for command in commands if DEPLOYER_RUN.search(command)]
            runs += len(deployer)
            if deployer:
                self.assertEqual(commands, deployer[:1], f'{where}: {deployer[0]} shares its block')
        self.assertGreaterEqual(runs, 5, 'preview, deployment, enablement, cleanup preview and cleanup were checked')


class ReadmeSenderSetupTests(unittest.TestCase):
    def test_readme_installs_and_runs_the_sender_from_a_venv_beside_the_checkout(self):
        where, setup = readme_sender_setup(self)
        self.assertEqual(setup, SENDER_SETUP, f'{where}: the sender commands differ from the shared sequence')

        # The commands run from the checkout root: the venv lands beside the
        # checkout, and the files the venv interpreter reads exist.
        venv = (ROOT / CREATE_VENV.split()[-1]).resolve()
        if venv == ROOT or ROOT in venv.parents:
            ignored = (ROOT / '.gitignore').read_text(encoding='utf-8').splitlines()
            self.assertIn(f'{venv.relative_to(ROOT).as_posix()}/', ignored, 'a venv inside the checkout must be ignored')
        for relative in ('scripts/requirements.txt', 'tests', 'scripts/Send-ThreatIntel.py'):
            self.assertTrue((ROOT / relative).exists(), relative)
        prerequisites = ' '.join(README.read_text(encoding='utf-8').split())
        self.assertIn('Python 3.12+ with `pip` and the `venv` module (on Debian and Ubuntu, install `python3-venv`)',
                      prerequisites)

    def test_no_readme_block_runs_bare_python_or_a_global_pip_install(self):
        for where, commands in fenced_blocks():
            for command in commands:
                self.assertIsNone(BARE_PYTHON.match(command), f'{where}: {command}')
                if PIP_INSTALL.search(command):
                    self.assertTrue(command.startswith('& $py -m pip install '), f'{where}: global pip install: {command}')
        # Inline commands in the prose follow the same rule; `pip` or `python3-venv` alone are names.
        source = README.read_text(encoding='utf-8')
        prose = re.sub(r'^```[^\n]*\n.*?^```', '', source, flags=re.MULTILINE | re.DOTALL)
        for span in re.findall(r'`([^`\n]+)`', prose):
            self.assertIsNone(re.match(r'(?:sudo )?(?:python3?|py|pip3?)(?:\.exe)? \S', span), f'README prose: {span}')

    def test_requirements_comment_installs_into_the_venv(self):
        comments = [line for line in REQUIREMENTS.read_text(encoding='utf-8').splitlines() if line.startswith('#')]
        installs = [line for line in comments if PIP_INSTALL.search(line)]
        self.assertTrue(installs, 'scripts/requirements.txt says how to install it')
        for line in installs:
            self.assertTrue(line.endswith(f': {INSTALL_DEPENDENCIES}'), f'scripts/requirements.txt: {line}')


class DeployerInstructionTests(unittest.TestCase):
    def test_preflight_chooses_the_interpreter_the_sender_steps_use(self):
        # The preflight runs the README's own choice, so on a Windows machine with only
        # the py launcher it reports that Python instead of probing python3 and python.
        deploy = DEPLOY_SCRIPT.read_text(encoding='utf-8')
        self.assertEqual([line for line in deploy.splitlines() if line.startswith('$sysPy = ')], [PYTHON_CHOICE])
        self.assertIn('& $sysPy --version', deploy)
        self.assertNotIn("'python3', 'python'", deploy)

    def test_help_examples_run_from_the_checkout_root_and_preview_first(self):
        examples = re.findall(r'^\.EXAMPLE\n[ \t]+(\S[^\n]*)$', DEPLOY_SCRIPT.read_text(encoding='utf-8'), re.MULTILINE)
        self.assertGreaterEqual(len(examples), 4, examples)
        self.assertTrue(any(re.search(r'\s-Destroy\b', example) for example in examples), examples)
        for index, example in enumerate(examples):
            self.assertTrue(example.startswith('./scripts/Deploy-Lab.ps1 '), f'not from the checkout root: {example}')
            if not WHATIF.search(example):
                previews = [without_whatif(earlier) for earlier in examples[:index] if WHATIF.search(earlier)]
                self.assertIn(example, previews, f'no earlier -WhatIf example previews {example}')


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 is not available')
class SenderSetupBehaviorTests(unittest.TestCase):
    def test_readme_interpreter_choice_creates_a_working_venv_beside_the_checkout(self):
        # Run the README's own interpreter choice, venv creation and venv path on
        # this platform. A Store alias, a missing venv module or a wrong
        # Scripts/bin layout fails here instead of at the reader's prompt.
        _, setup = readme_sender_setup(self)
        with tempfile.TemporaryDirectory() as temp:
            checkout = Path(temp) / 'checkout'
            checkout.mkdir()
            script = '\n'.join([
                "$ErrorActionPreference = 'Stop'",
                '$PSNativeCommandUseErrorActionPreference = $false',
                'Set-Location -LiteralPath $env:CCF_TEST_CHECKOUT',
                *setup[:setup.index(INSTALL_DEPENDENCIES)],
                "& $py -c \"import sys; print('VENV=' + str(sys.prefix != sys.base_prefix)); print('PREFIX=' + sys.prefix)\"",
                '& $py -m pip --version',
                "'SYSPY=' + $sysPy",
            ])
            result = run_pwsh(script, CCF_TEST_CHECKOUT=str(checkout))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('VENV=True', result.stdout)
            prefix = re.search(r'^PREFIX=(.+)$', result.stdout, re.MULTILINE).group(1).strip()
            self.assertTrue(os.path.samefile(prefix, Path(temp) / 'ccf-sender-venv'), prefix)
            self.assertFalse((checkout / 'ccf-sender-venv').exists())
            chosen = re.search(r'^SYSPY=(.+)$', result.stdout, re.MULTILINE).group(1).strip()
            self.assertIn(chosen, ('py', 'python') if os.name == 'nt' else ('python3',))

    def test_each_native_failure_stops_the_printed_sequence_before_the_next_stage(self):
        # Execute the README's exact commands with native stand-ins. A real venv
        # runs local fake pip/unittest modules and a fake sender, so no package
        # download, feed request or cloud request is possible. The printed steps
        # are independently required below to be byte-for-byte the same sequence.
        _, setup = readme_sender_setup(self)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            checkout = directory / 'checkout'
            checkout.mkdir()
            (checkout / 'scripts').mkdir()
            venv = directory / 'ccf-sender-venv'
            created = subprocess.run([sys.executable, '-m', 'venv', '--without-pip', str(venv)],
                                     capture_output=True, text=True, check=False, timeout=120)
            self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
            commands = directory / 'commands'
            commands.mkdir()
            log = directory / 'stages.txt'

            def stand_in(stage):
                return (
                    'import os\nfrom pathlib import Path\n'
                    f'stage = {stage!r}\n'
                    "with Path(os.environ['CCF_STAGE_LOG']).open('a', encoding='utf-8') as stream:\n"
                    "    stream.write(stage + '\\n')\n"
                    "raise SystemExit(42 if os.environ.get('CCF_FAIL_STAGE') == stage else 0)\n"
                )

            launcher_script = commands / 'launcher.py'
            launcher_script.write_text(stand_in('venv'), encoding='utf-8')
            # The system-interpreter stand-in records the venv stage; the venv
            # above is already present so a success can continue without network.
            native_python = getattr(sys, '_base_executable', sys.executable)
            if os.name == 'nt':
                (commands / 'py.cmd').write_text(
                    f'@echo off\r\n"{native_python}" "{launcher_script}" %*\r\nexit /b %errorlevel%\r\n',
                    encoding='utf-8',
                )
            else:
                launcher = commands / 'python3'
                launcher.write_text(f'#!/bin/sh\nexec {shlex.quote(native_python)} {shlex.quote(str(launcher_script))} "$@"\n',
                                    encoding='utf-8')
                launcher.chmod(0o755)
            for relative, stage in [('pip.py', 'pip'), ('unittest.py', 'tests'), ('scripts/Send-ThreatIntel.py', 'sender')]:
                (checkout / relative).write_text(stand_in(stage), encoding='utf-8')

            for index, (stage, message) in enumerate((*STAGE_FAILURES, ('', ''))):
                with self.subTest(failing_stage=stage or 'none'):
                    log.unlink(missing_ok=True)
                    script = '\n'.join([
                        "$ErrorActionPreference = 'Continue'",
                        '$PSNativeCommandUseErrorActionPreference = $false',
                        'Set-Location -LiteralPath $env:CCF_TEST_CHECKOUT',
                        *setup,
                        "'SETUP_COMPLETED'",
                    ])
                    result = run_pwsh(script, CCF_TEST_CHECKOUT=str(checkout), CCF_STAGE_LOG=str(log),
                                      CCF_FAIL_STAGE=stage, PATH=f"{commands}{os.pathsep}{os.environ.get('PATH', '')}")
                    expected = [name for name, _ in STAGE_FAILURES[:index + 1]]
                    self.assertEqual(log.read_text(encoding='utf-8').splitlines(), expected,
                                     result.stdout + result.stderr)
                    if stage:
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn(message, result.stdout + result.stderr)
                        self.assertNotIn('SETUP_COMPLETED', result.stdout)
                    else:
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn('SETUP_COMPLETED', result.stdout)


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 is not available')
class PrintedNextStepsTests(unittest.TestCase):
    HARNESS = r'''
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:CCF_TEST_DEPLOY, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Deployment script did not parse' }
$statements = @($ast.EndBlock.Statements | Where-Object {
    $_.Extent.Text -match '^\$quotedLabRoot\s*=' -or
    ($_.Extent.Text -match '^Write-Host @"' -and $_.Extent.Text.Contains('CCF_CLIENT_SECRET'))
})
$LabRoot = $env:CCF_TEST_LAB_ROOT
$ScriptDir = Join-Path $LabRoot 'scripts'
foreach ($statement in $statements) { . ([scriptblock]::Create($statement.Extent.Text)) }
'''

    def test_step_6_prints_the_readme_sender_setup_from_the_checkout_root(self):
        with tempfile.TemporaryDirectory() as temp:
            # A space and an apostrophe prove the printed path is a valid PowerShell literal.
            lab_root = Path(temp) / "lab o'brien checkout"
            elsewhere = Path(temp) / 'elsewhere'
            lab_root.mkdir()
            elsewhere.mkdir()
            result = run_pwsh(self.HARNESS, CCF_TEST_DEPLOY=str(DEPLOY_SCRIPT), CCF_TEST_LAB_ROOT=str(lab_root))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            lines = result.stdout.splitlines()
            step_6 = next((i for i, line in enumerate(lines) if re.match(r'\s*6\. ', line)), None)
            step_7 = next((i for i, line in enumerate(lines) if re.match(r'\s*7\. ', line)), None)
            self.assertTrue(step_6 is not None and step_7 is not None and step_6 < step_7, result.stdout)
            for line in lines:
                self.assertIsNone(re.search(r'\bpython3? (?:-m pip\b|.*\.py\b)', line), f'bare interpreter: {line}')
            # Commands are the lines indented as code under their step; the rest is prose.
            printed = [re.sub(r'\s+', ' ', line).strip() for line in lines if line.startswith(' ' * 7)]
            for command in printed:
                self.assertIsNone(BARE_PYTHON.match(command), command)
                if PIP_INSTALL.search(command):
                    self.assertTrue(command.startswith('& $py -m pip install '), f'global pip install: {command}')
            raw = [line.strip() for line in lines[step_6 + 1:step_7] if line.startswith(' ' * 7)]
            step = [re.sub(r'\s+', ' ', line) for line in raw]
            self.assertEqual(len(step), len(SENDER_SETUP) + 2, step)
            self.assertTrue(step[0].startswith("Push-Location -LiteralPath '"), step[0])
            self.assertEqual(tuple(step[1:-1]), SENDER_SETUP)
            self.assertEqual(step[-1], 'Pop-Location')

            # Run the printed Push-Location line itself from another directory.
            moved = run_pwsh('\n'.join([
                "$ErrorActionPreference = 'Stop'",
                'Set-Location -LiteralPath $env:CCF_TEST_ELSEWHERE',
                raw[0],
                "'AT=' + (Get-Location).ProviderPath",
                step[-1],
                "'BACK=' + (Get-Location).ProviderPath",
            ]), CCF_TEST_ELSEWHERE=str(elsewhere))
            self.assertEqual(moved.returncode, 0, moved.stdout + moved.stderr)
            at = re.search(r'^AT=(.+)$', moved.stdout, re.MULTILINE).group(1).strip()
            back = re.search(r'^BACK=(.+)$', moved.stdout, re.MULTILINE).group(1).strip()
            self.assertTrue(os.path.samefile(at, lab_root), at)
            self.assertTrue(os.path.samefile(back, elsewhere), back)


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 is not available')
class PreflightPythonCheckTests(unittest.TestCase):
    # The deployer's own preflight statements, under its own error preferences, with
    # only stand-in interpreters on PATH.
    HARNESS = r'''
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:CCF_TEST_DEPLOY, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Deployment script did not parse' }
$statements = @($ast.EndBlock.Statements | Where-Object { $_.Extent.Text -match '(?<!`)\$(?:sysPy|pythonVersion)\b' })
if ($statements.Count -lt 2) { throw 'Expected the Python preflight statements' }
$env:PATH = $env:CCF_TEST_BIN
foreach ($statement in $statements) { . ([scriptblock]::Create($statement.Extent.Text)) }
'''
    # Called with arguments, the Windows python and python3 shortcuts that open the
    # Microsoft Store print this and return an error code instead of running Python.
    STORE_ALIAS = (9009, 'Python was not found; run without arguments to install from the Microsoft Store')

    def run_preflight(self, commands):
        with tempfile.TemporaryDirectory() as temp:
            for name, (exit_code, text) in commands.items():
                write_fake_command(Path(temp), name, exit_code, text)
            result = run_pwsh(self.HARNESS, CCF_TEST_DEPLOY=str(DEPLOY_SCRIPT), CCF_TEST_BIN=temp)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_preflight_reports_the_python_that_the_sender_steps_use(self):
        if os.name == 'nt':
            cases = [
                # A python.org install without "Add Python to PATH": only the launcher works.
                (dict(py=(0, 'Python 3.12.97'), python=self.STORE_ALIAS, python3=self.STORE_ALIAS),
                 'Python (py): Python 3.12.97'),
                # A Microsoft Store install has no py launcher.
                (dict(python=(0, 'Python 3.12.98'), python3=self.STORE_ALIAS), 'Python (python): Python 3.12.98'),
                (dict(python=self.STORE_ALIAS, python3=self.STORE_ALIAS), "Python 3 not found as 'python'"),
            ]
        else:
            cases = [
                (dict(python3=(0, 'Python 3.12.99'), python=(0, 'Python 3.12.98')), 'Python (python3): Python 3.12.99'),
                # The sender steps run python3 off Windows, so another python does not count.
                (dict(python=(0, 'Python 3.12.98')), "Python 3 not found as 'python3'"),
            ]
        for commands, expected in cases:
            with self.subTest(commands=sorted(commands)):
                output = self.run_preflight(commands)
                self.assertIn(expected, output)
                self.assertEqual(output.count('Python 3 not found') + output.count('  Python ('), 1, output)


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 is not available')
class PrintedCleanupTests(unittest.TestCase):
    RENDER = r'''
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:CCF_TEST_DEPLOY, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Deployment script did not parse' }
$statements = @($ast.EndBlock.Statements | Where-Object {
    $_.Extent.Text -match '(?<!`)\$quotedDeployScript\b' -or
    ($_.Extent.Text -match '^Write-Host' -and $_.Extent.Text -match '\s-Destroy\b')
})
$ScriptDir = Join-Path $env:CCF_TEST_LAB_ROOT 'scripts'
$ProjectName = 'audit-test'
foreach ($statement in $statements) { . ([scriptblock]::Create($statement.Extent.Text)) }
'''
    # Azure reads succeed for an owned group; any other call is refused.
    AZ_MOCK = r'''
$ErrorActionPreference = 'Stop'
function global:az {
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'account') { return '{"id":"sub","tenantId":"tenant","name":"Fixture"}' }
    if ($args[0] -eq 'group' -and $args[1] -eq 'exists') { return 'true' }
    if ($args[0] -eq 'group' -and $args[1] -eq 'show') {
        return '{"name":"audit-test-rg","tags":{"nlzt-owner":"00000000-0000-0000-0000-000000000001"}}'
    }
    throw 'MUTATION OR UNEXPECTED CALL REFUSED BY TEST'
}
'''

    def test_printed_cleanup_previews_first_and_runs_from_any_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            # A space, an apostrophe, brackets and $HOME prove the printed path is a
            # PowerShell literal that is neither a wildcard nor expanded.
            lab_root = Path(temp) / "lab o'brien [x] $HOME checkout"
            elsewhere = Path(temp) / 'elsewhere'
            shutil.copytree(ROOT / 'scripts', lab_root / 'scripts')
            shutil.copytree(ROOT / 'connector', lab_root / 'connector')
            elsewhere.mkdir()
            state = dict(schemaVersion=1, projectName='audit-test', subscriptionId='sub', tenantId='tenant',
                         resourceGroup='audit-test-rg', workspaceName='audit-test-law',
                         ownerToken='00000000-0000-0000-0000-000000000001')
            (lab_root / '.ccf-push-lab-state-audit-test.json').write_text(json.dumps(state), encoding='utf-8')

            rendered = run_pwsh(self.RENDER, CCF_TEST_DEPLOY=str(DEPLOY_SCRIPT), CCF_TEST_LAB_ROOT=str(lab_root))
            self.assertEqual(rendered.returncode, 0, rendered.stdout + rendered.stderr)
            lines = [line.strip() for line in rendered.stdout.splitlines()]
            commands = [index for index, line in enumerate(lines) if re.search(r'\s-Destroy\b', line)]
            self.assertEqual(len(commands), 2, f'a preview and a cleanup, each on its own line: {rendered.stdout}')
            preview, cleanup = (lines[index] for index in commands)
            self.assertTrue(WHATIF.search(preview), f'the cleanup preview comes first: {rendered.stdout}')
            self.assertEqual(cleanup, without_whatif(preview))
            self.assertEqual(lines[commands[0] - 1], 'Preview the cleanup first:')
            self.assertEqual(lines[commands[1] - 1], 'After reviewing the preview, run the cleanup:')

            # Run the printed preview line itself from another directory: it reaches this
            # checkout's script and manifest and deletes nothing.
            previewed = run_pwsh('\n'.join([self.AZ_MOCK, 'Set-Location -LiteralPath $env:CCF_TEST_ELSEWHERE', preview]),
                                 CCF_TEST_ELSEWHERE=str(elsewhere))
            self.assertEqual(previewed.returncode, 0, previewed.stdout + previewed.stderr)
            self.assertIn('Cleanup preview complete; no resources were deleted.', previewed.stdout)
            self.assertNotIn('MUTATION OR UNEXPECTED', previewed.stdout + previewed.stderr)
            self.assertTrue((lab_root / '.ccf-push-lab-state-audit-test.json').exists())


if __name__ == '__main__':
    unittest.main()

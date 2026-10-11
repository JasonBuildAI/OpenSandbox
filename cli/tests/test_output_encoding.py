# Copyright 2026 The OpenSandbox Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""CLI output must survive streams that cannot encode emoji.

The CLI prints emoji and box-drawing characters, which a legacy Windows code
page (cp936, cp1252, ...) or a POSIX ``C`` locale cannot represent. Rich and
Click used to raise ``UnicodeEncodeError`` and the command exited 1 with a
traceback after already doing its work. ``CliRunner(charset=...)`` reproduces
those stream encodings on any host.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from opensandbox_cli.main import cli


def _gbk_runner() -> CliRunner:
    """Return a runner whose captured output uses a legacy Windows code page."""
    return CliRunner(charset="gbk")


class TestNonUtf8Streams:
    def test_help_output_is_not_aborted(self) -> None:
        runner = _gbk_runner()

        root_help = runner.invoke(cli, ["--help"])
        assert root_help.exit_code == 0
        assert "Usage:" in root_help.output

        config_help = runner.invoke(cli, ["config", "--help"])
        assert config_help.exit_code == 0
        assert "Manage CLI configuration" in config_help.output

    def test_config_messages_are_not_aborted(self, tmp_path: Path) -> None:
        runner = _gbk_runner()
        cfg_path = tmp_path / "config.toml"

        init = runner.invoke(cli, ["--config", str(cfg_path), "config", "init"])
        assert init.exit_code == 0
        assert cfg_path.exists()
        assert "Config file created" in init.output

        set_result = runner.invoke(
            cli,
            ["--config", str(cfg_path), "config", "set", "connection.domain", "team.host"],
        )
        assert set_result.exit_code == 0
        assert 'domain = "team.host"' in cfg_path.read_text(encoding="utf-8")

    def test_real_errors_still_fail(self, tmp_path: Path) -> None:
        result = _gbk_runner().invoke(
            cli,
            [
                "--config",
                str(tmp_path / "missing.toml"),
                "config",
                "set",
                "connection.domain",
                "team.host",
            ],
        )

        assert result.exit_code != 0
        assert "Config file not found" in result.output



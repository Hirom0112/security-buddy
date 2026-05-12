"""Seed attack library loader for the Red Team agent.

Reads JSON seed files from the seeds/ directory, validates each object via
Pydantic, and enforces cross-file invariants (unique seed_id, subcategory
consistency).

Import boundary: this module may only import from:
  - src.agents.red_team (its own package)
  - Standard library
  - Pydantic (third-party, pre-approved)

It must NOT import from src.agents.judge, src.agents.orchestrator,
src.agents.documentation, src.agents.patch, src.repositories, or src.routes.
"""

import json
from pathlib import Path

from pydantic import ValidationError

from src.agents.red_team.types import SeedAttack

# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class DuplicateSeedIdError(Exception):
    """Raised when two seeds share the same seed_id.

    Duplicate seed_ids break reproducibility — the same ID would reference
    two different adversarial patterns, corrupting coverage metrics.
    """

    def __init__(self, seed_id: str, files: list[str]) -> None:
        self.seed_id = seed_id
        self.files = files
        super().__init__(
            f"Duplicate seed_id '{seed_id}' found in files: {files}. "
            "Each seed_id must be unique across the entire library."
        )


class SeedSubcategoryMismatchError(Exception):
    """Raised when a seed's 'subcategory' field does not match its filename.

    Convention: seeds/foo__bar.json must contain seeds with subcategory='foo/bar'.
    A mismatch means the file is mis-placed or the seed is mis-labelled.
    """

    def __init__(self, seed_id: str, file_path: Path, expected: str, actual: str) -> None:
        self.seed_id = seed_id
        self.file_path = file_path
        self.expected_subcategory = expected
        self.actual_subcategory = actual
        super().__init__(
            f"Seed '{seed_id}' in '{file_path.name}' has subcategory='{actual}' "
            f"but filename implies subcategory='{expected}'. "
            "Rename the file or fix the seed's subcategory field."
        )


# ---------------------------------------------------------------------------
# Filename ↔ subcategory convention
# ---------------------------------------------------------------------------

_SEEDS_DIR_DEFAULT = Path(__file__).parent / "seeds"


def _filename_to_subcategory(stem: str) -> str:
    """Convert a seed filename stem to a subcategory string.

    Convention: double-underscore separates category from subcategory.
    'foo__bar' → 'foo/bar'
    'prompt_injection__indirect_via_upload' → 'prompt_injection/indirect_via_upload'
    """
    return stem.replace("__", "/", 1)


def _subcategory_to_filename_stem(subcategory: str) -> str:
    """Inverse of _filename_to_subcategory.

    'foo/bar' → 'foo__bar'
    """
    return subcategory.replace("/", "__", 1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_seeds_for_subcategory(
    subcategory: str,
    *,
    seeds_dir: Path | None = None,
) -> list[SeedAttack]:
    """Load and validate seeds for a single subcategory.

    Args:
        subcategory: The subcategory key, e.g.
            'prompt_injection/indirect_via_upload'. Used to derive the
            filename: 'seeds/prompt_injection__indirect_via_upload.json'.
        seeds_dir: Override the default seeds directory. Defaults to
            Path(__file__).parent / "seeds".

    Returns:
        A list of validated SeedAttack objects for the given subcategory.

    Raises:
        FileNotFoundError: If no JSON file exists for the subcategory.
        pydantic.ValidationError: If any seed object fails Pydantic validation.
        SeedSubcategoryMismatchError: If any seed's subcategory field does not
            match the expected subcategory derived from the filename.
    """
    resolved_dir = seeds_dir if seeds_dir is not None else _SEEDS_DIR_DEFAULT
    stem = _subcategory_to_filename_stem(subcategory)
    file_path = resolved_dir / f"{stem}.json"

    if not file_path.exists():
        raise FileNotFoundError(
            f"No seed file found for subcategory '{subcategory}'. Expected: {file_path}"
        )

    raw: list[object] = json.loads(file_path.read_text(encoding="utf-8"))

    seeds: list[SeedAttack] = []
    for i, item in enumerate(raw):
        try:
            seed = SeedAttack.model_validate(item)
        except ValidationError as exc:
            raise ValidationError.from_exception_data(
                title=f"Seed #{i} in {file_path.name}",
                line_errors=exc.errors(),  # type: ignore[arg-type]
            ) from exc

        expected_subcategory = _filename_to_subcategory(stem)
        if seed.subcategory != expected_subcategory:
            raise SeedSubcategoryMismatchError(
                seed_id=seed.seed_id,
                file_path=file_path,
                expected=expected_subcategory,
                actual=seed.subcategory,
            )

        seeds.append(seed)

    return seeds


def load_all_seeds(
    *,
    seeds_dir: Path | None = None,
) -> dict[str, list[SeedAttack]]:
    """Load and validate all seed files from the seeds directory.

    Returns a mapping of subcategory → list[SeedAttack]. Applies cross-file
    invariants: unique seed_ids, subcategory consistency.

    Args:
        seeds_dir: Override the default seeds directory. Defaults to
            Path(__file__).parent / "seeds".

    Returns:
        dict mapping subcategory strings to lists of validated SeedAttack
        objects. Only subcategories that have a corresponding .json file are
        included.

    Raises:
        pydantic.ValidationError: If any seed object fails Pydantic validation.
        DuplicateSeedIdError: If any seed_id appears in more than one seed
            across all files.
        SeedSubcategoryMismatchError: If any seed's subcategory field does not
            match the subcategory implied by its filename.
    """
    resolved_dir = seeds_dir if seeds_dir is not None else _SEEDS_DIR_DEFAULT

    result: dict[str, list[SeedAttack]] = {}
    seen_ids: dict[str, str] = {}  # seed_id → filename that first declared it

    for json_file in sorted(resolved_dir.glob("*.json")):
        subcategory = _filename_to_subcategory(json_file.stem)
        seeds = load_seeds_for_subcategory(subcategory, seeds_dir=resolved_dir)

        for seed in seeds:
            if seed.seed_id in seen_ids:
                raise DuplicateSeedIdError(
                    seed_id=seed.seed_id,
                    files=[seen_ids[seed.seed_id], json_file.name],
                )
            seen_ids[seed.seed_id] = json_file.name

        result[subcategory] = seeds

    return result

import logging
from pathlib import Path
from typing import List, Optional, Tuple, Union

import chardet


def read_text_safely(
    path: Union[str, Path],
    fallback_encodings: Optional[List[str]] = None,
    return_encoding: bool = False,
) -> Union[str, Tuple[str, str]]:
    """
    Read text from a file with encoding detection and fallbacks.

    Args:
        path: Path to the file.
        fallback_encodings: List of encodings to try if detection fails. Defaults to ['utf-8', 'latin-1'].
        return_encoding: If True, return a tuple (text, encoding_used).

    Returns:
        The file content as a string, or (content, encoding_used) if return_encoding is True.

    Raises:
        FileNotFoundError: If the file does not exist.
        UnicodeDecodeError: If all encoding attempts fail.
    """
    logger = logging.getLogger(__name__)
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"No such file: {path}")

    with path.open('rb') as f:
        raw = f.read()

    guess = chardet.detect(raw) or {}
    enc = guess.get("encoding")
    tried_encodings = []

    if fallback_encodings is None:
        fallback_encodings = ['utf-8', 'latin-1']

    encodings_to_try = [enc] if enc else []
    encodings_to_try += [e for e in fallback_encodings if e and e != enc]

    for encoding in encodings_to_try:
        tried_encodings.append(encoding)
        try:
            text = raw.decode(encoding, errors="strict")
        except UnicodeDecodeError as strict_err:
            logger.debug(f"Strict decoding failed with '{encoding}': {strict_err}. Retrying with errors='replace'.")
            try:
                text = raw.decode(encoding, errors="replace")
            except Exception as e:
                logger.debug(f"Failed decoding with '{encoding}': {e}")
                continue  # try next encoding
        if encoding == enc:
            logger.info(f"Detected encoding '{encoding}' used for file: {path}")
        else:
            logger.warning(
                f"Fallback encoding '{encoding}' used for file: {path} "
                f"(detected: '{enc}', tried: {tried_encodings})"
            )
        return (text, encoding) if return_encoding else text

    # If all encodings fail, raise an error
    logger.error(f"All encoding attempts failed for file: {path} (tried: {tried_encodings})")
    raise UnicodeDecodeError(
        encodings_to_try[-1] if encodings_to_try else "unknown",
        raw,
        0,
        len(raw),
        "All encoding attempts failed."
    )

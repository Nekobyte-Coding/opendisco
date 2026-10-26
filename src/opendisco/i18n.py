"""The app's languages: English, Spanish, Brazilian Portuguese and Japanese.

Every text the app's windows show is written in English in the code and wrapped where it's shown:
_("Ready.") or, with values in it, tr("Found {count} devices.", count=n), so one translation covers
every value. Texts kept in module-level constants are marked with N_() and wrapped where they're
shown. resources/locale/<language>.json maps each English text to its translation; a text missing
there stays English. The language is English until the app sets it at startup (set_language), so
the command line, which shares core's texts, always speaks English.
packaging/i18n_check.py lists every wrapped text and what each catalog lacks or no longer needs."""
from __future__ import annotations

import json
import os
import sys
import textwrap
import unicodedata
from pathlib import Path

FOLDER = Path(__file__).parent / "resources" / "locale"
ENGLISH = "en"
SYSTEM = "system"  # settings.json's "language" when the system's language decides
# Each language offered, by settings.json's "language" value, in its own name
LANGUAGES = {"en": "English", "es": "Español", "pt-BR": "Português (Brasil)", "ja": "日本語"}
SETTING = "language"

language = ENGLISH
_catalog: dict = {}


def _(text: str) -> str:
    """The text in the app's language (English where it has no translation)."""
    return _catalog.get(text, text) if text else text


def tr(template: str, **values) -> str:
    """A text with values in it: the translated template, filled in. A translation whose
    placeholders don't match the English ones falls back to English rather than failing."""
    text = _catalog.get(template, template)
    if not values:
        return text
    try:
        return text.format(**values)
    except (KeyError, IndexError, ValueError):
        return template.format(**values)


def sentences(*texts: str) -> str:
    """Sentences one after another: a space apart, but none in Japanese."""
    return ("" if language == "ja" else " ").join(text for text in texts if text)


def N_(text: str) -> str:
    """Marks a text kept in a constant for translation; _() translates it where it's shown."""
    return text


def catalog(code: str) -> dict:
    """A language's translations, English text -> translated text ({} for English or a missing file)."""
    if code == ENGLISH:
        return {}
    try:
        found = json.loads((FOLDER / f"{code}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in found.items() if isinstance(v, str) and v and not k.startswith("@")}


def set_language(code: str) -> str:
    """Speak this language from now on (one of LANGUAGES; anything else is English)."""
    global language, _catalog
    language = code if code in LANGUAGES else ENGLISH
    _catalog = catalog(language)
    return language


def match(tag: str) -> str | None:
    """The language offered for a system language tag (ja-JP, pt_PT.UTF-8, es-419...): any
    Portuguese is pt-BR, any Spanish es; None for a language not offered."""
    base = tag.replace("_", "-").split(".")[0].split("@")[0].split("-")[0].lower()
    return {"en": "en", "es": "es", "pt": "pt-BR", "ja": "ja"}.get(base)


def system_languages() -> list:
    """The system's languages, most preferred first: macOS's and iOS's preferred languages,
    Windows's display language, Android's locales, or on Linux the locale variables."""
    try:
        if sys.platform in ("darwin", "ios") or getattr(sys.implementation, "_multiarch", "").endswith(
                ("iphoneos", "iphonesimulator")):
            from rubicon.objc import ObjCClass
            return [str(tag) for tag in ObjCClass("NSLocale").preferredLanguages]
        if sys.platform == "android" or hasattr(sys, "getandroidapilevel"):
            from java import jclass
            try:
                return str(jclass("android.os.LocaleList").getDefault().toLanguageTags()).split(",")
            except Exception:  # (before Android 7)
                return [str(jclass("java.util.Locale").getDefault().toLanguageTag())]
        if sys.platform == "win32":
            import ctypes
            kernel32 = ctypes.windll.kernel32
            name = ctypes.create_unicode_buffer(85)
            if kernel32.LCIDToLocaleName(kernel32.GetUserDefaultUILanguage(), name, 85, 0):
                return [name.value]
            return []
    except Exception:  # whatever the platform's call raises: English, then
        return []
    # Linux and the rest: gettext's order, where LANGUAGE (a list) counts unless the locale is C
    found = [os.environ.get(name, "") for name in ("LC_ALL", "LC_MESSAGES", "LANG")]
    locale = next((value for value in found if value), "")
    if locale.split(".")[0] in ("C", "POSIX"):
        return []
    return [tag for tag in os.environ.get("LANGUAGE", "").split(":") if tag] + ([locale] if locale else [])


def choose(setting: str | None) -> str:
    """The language to speak for settings.json's "language": its own, or with "system" (or none)
    the first of the system's languages offered here, else English."""
    if setting in LANGUAGES:
        return setting
    return next((code for code in map(match, system_languages()) if code), ENGLISH)


def _wide(char: str) -> bool:
    return unicodedata.east_asian_width(char) in ("W", "F")


# Japanese never starts a line with these, nor ends one with an opening bracket
_NO_START = set("、。，．・：；？！」』）】〕〉》ー々ゝゞぁぃぅぇぉっゃゅょゎァィゥェォッャュョヮヵヶ…,.:;?!)]}")
_NO_END = set("「『（【〔〈《([{")


def width(text: str) -> int:
    """How wide the text is in narrow characters: Japanese characters count two."""
    return sum(2 if _wide(char) else 1 for char in text)


def fill(text: str, columns: int) -> str:
    """textwrap.fill for any language: Japanese has no spaces to break at, and its characters are
    twice as wide, so a line of it breaks between characters at half as many."""
    if not any(_wide(char) for char in text):
        return textwrap.fill(text, columns)
    lines, line = [], ""
    for unit in _units(text):
        if unit.isspace() and not line:
            continue
        if line and width(line) + width(unit.rstrip()) > columns and unit[0] not in _NO_START \
                and line[-1] not in _NO_END:
            lines.append(line.rstrip())
            line = "" if unit.isspace() else unit
        else:
            line += unit
    return "\n".join([*lines, line.rstrip()] if line.strip() else lines)


def _units(text: str):
    """The pieces a line may break between: each Japanese character, each other word, each space."""
    word = ""
    for char in text:
        if _wide(char) or char.isspace():
            if word:
                yield word
                word = ""
            yield char
        else:
            word += char
    if word:
        yield word

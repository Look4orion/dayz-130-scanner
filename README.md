# DayZ 1.30 Mod Scanner

Checks DayZ mods for the known 1.30 breaking changes, and whether the same build still compiles
on 1.29. It reads the mod's scripts and compares them with an index of the vanilla 1.29 and 1.30
scripts; it does not run anything.

**Web version:** drop a mod folder or its `.pbo` files on the page and get a report. The scan runs
in your browser and your files are never uploaded (the page's Content-Security-Policy only lets it
load its own files).

**Command line:** the same checks in Python 3, standard library only (see below).

A clean result means no *known* breaker was found, not that the mod works. Read each hit in the
code before reporting it to an author: the scanner matches by name, so a mod's own field that
shares a name with something vanilla removed shows up as a "check by hand" hit.

## What it checks

Each script file is read twice, as a 1.29 server and as a 1.30 server compile it: `#ifdef` /
`#ifndef` `DAYZ_1_29` / `DAYZ_1_30` blocks are resolved for that version (other defines, such as
`SERVER` or a mod's own, keep both branches). Comments are ignored.

**1.30** (`BREAK`, `RISK`, `INFO`):
- **Overrides** of a vanilla method that is gone in 1.30, or whose signature or return type changed.
  Only reported when the mod's signature matched 1.29, which filters parser noise.
- **Name clashes with methods vanilla added in 1.30.** A mod method (not `override`) with the same
  name as a new vanilla method in an ancestor class, or (for `modded class X`) in any subclass of X.
  This is what breaks Code Lock's `ItemBase.GetCodeLock()` against 1.30's `Fence.GetCodeLock()`.
- **Uses** of removed methods, fields and classes. These are `RISK` only: the same name can belong to
  another mod's class, so check the receiver's type by hand.
- **Known patterns:** `modded class GameConstants`, `#include "$profile..."`, `FindFile` (folder
  listings of `$profile:`/`$mission:` return nothing on 1.30), `ChangeGameFocus` (global input focus
  freezes menu input on 1.30), `GetFluidCapacityScript`, `CreateInInventory`, `Fill`.
- **Silent breakers** (compile, but 1.30 vanilla never calls them): overrides of `OnCEUpdate`
  (1.30 calls `OnCEIterate`), the old `GetNoiseReduction`/`GetNoiseReductionByWeather`, and
  `AddExplosionEffectForSurface` registrations.
- **Car lights** (`INFO`): overrides of `CreateFrontLight`/`CreateRearLight` are never called on
  1.30; the car still gets vanilla's default headlights, not its own brightness/range/colour.
- **Wrong version gates** (`RISK`): `#ifdef DAYZ_1_30` (off again on 1.31; use `#ifndef DAYZ_1_29`)
  and `BUILD_EXPERIMENTAL` (gone on 1.30 stable).
- **Methods 1.30 made protected** (`RISK`), called from outside the class.
- **CfgMods script paths with backslashes** (`BREAK`): 1.30 compiles none of that module's scripts
  and logs nothing. Only `*ScriptModule` entries count; image sets with backslashes still load.
- `INFO`: calls and overrides of methods 1.30 marks `[Obsolete]` (they still compile).

**1.29** (`BREAK_129`, `RISK_129`), for builds that must still run on a 1.29 server:
- `modded class` of, or `extends`, a class that only exists from 1.30.
- Overrides of a method that only exists from 1.30, or written with its 1.30 signature.
- `RISK_129`: calls of methods and uses of classes that only exist from 1.30.

Names that any scanned mod declares count as known, so scan mods that depend on each other together.

## Known limits

- The parser is regex and brace based. Defines other than `DAYZ_1_29`/`DAYZ_1_30` are not
  evaluated, so code under `#ifdef SERVER` or a mod's own define counts for both branches.
- Scrambled (obfuscated) PBOs parse, but hits there need a closer look. The command-line
  extractor writes each script to disk, and in heavily scrambled PBOs Windows refuses a few of
  the decoy files' paths (about 1-2% in the worst mods tested); the web version reads every file
  in memory and has no such gap.
- Config is not checked (for example, 1.30 needing a `<wheel>_Ruined` class for every wheel).

## Command line

Python 3, no packages to install. Run each script with `python -I`, and keep extracted mod sources
in their own folder: they are third-party code.

1. **Mod list**, `mods.tsv`: one line per mod, tab separated: `<number>\t<mod|serverMod>\t<@Folder>`.
   You can take it from a server's command line (`-mod=...;...`, split on `;`).
2. **Extract the scripts** from the mods (a folder holding the `@Folder`s) into `modsrc`:
   ```
   python -I python/extract.py mods.tsv <mods folder> modsrc
   ```
3. **Scan**:
   ```
   python -I python/scan130.py docs/vanilla.json modsrc scan.json mods.tsv <mods folder>
   ```
   `scan.json` lists, per mod, the hits by level with file and line. The last two arguments add the
   CfgMods script path check.

Also included: `python/deps.py` (mod-to-mod dependencies from `requiredAddons`), `python/modpaths.py`
(every backslash script path), and `python/hiddendeps.py` (dependencies a mod uses but doesn't
declare; needs the vanilla config files unpacked).

## The vanilla index

`docs/vanilla.json` holds the names and signatures of the vanilla classes, methods and fields (no
code), built from DayZ 1.29.163709 and 1.30.164014. To rebuild it after a game update, point
`vanilla.py` at the `scripts.pbo` in each game version's `dta` folder (server or client):
```
python -I python/vanilla.py <1.29 dta/scripts.pbo> <1.30 dta/scripts.pbo> docs/vanilla.json 1.29.xxxxxx 1.30.xxxxxx
```

## Development

The web scanner in `docs/js` is a port of the Python scanner; the two must agree. `tools/parity.mjs`
runs the web code in Node over a mod list, and `tools/compare.py` checks the two reports hit for hit:
```
python -I python/scan130.py docs/vanilla.json modsrc py.json mods.tsv <mods folder>
node tools/parity.mjs docs/vanilla.json mods.tsv <mods folder> js.json
python -I tools/compare.py py.json js.json
```
To try the page locally, serve `docs` (for example `python -m http.server -d docs`): browsers don't
run module scripts from `file://`.

## License

MIT. See `LICENSE`.

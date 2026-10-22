# DayZ Mod Scanner

Checks DayZ mods for known breaking changes on the current stable version (1.30). It's kept up
to date: when Bohemia opens a new experimental version, the scanner adds its changes, so modders
can see what will break before it reaches stable. It also checks whether a build still compiles
on 1.29. It reads the mod's scripts and compares them with an index of the vanilla 1.29 and 1.30
scripts; it does not run anything.

**Web version:** https://look4orion.github.io/dayz-130-scanner/. Drop a mod folder or its `.pbo`
files on the page and get a report. The scan runs in your browser and your files are never uploaded:
the page's Content-Security-Policy only lets it load its own files, plus a GoatCounter visit counter
(no cookies) that records that the page was opened or a scan was run, never anything about your files.

**Command line:** the same checks in Python 3, standard library only (see below).

Made by Rook: [my DayZ mods on the Workshop](https://steamcommunity.com/id/rook1969/myworkshopfiles/) ·
[support me on Ko-fi](https://ko-fi.com/rookmod).

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
  A subclass method isn't a clash when it has the same parameters and returns the mod's return type
  or a subclass of it: vanilla's method then overrides the mod's. Returning `ItemBase` instead of
  `CodeLock` is how a fix makes `DigitalCodeLock Fence.GetCodeLock()` compile.
- **Uses** of removed methods, fields and classes. These are `RISK` only: the same name can belong to
  another mod's class, so check the receiver's type by hand.
- **`FindFile`:** not a 1.30 check any more. 1.30.164078 listed nothing for `$profile:`/`$mission:`
  folders (DZEXP-134); 1.30.164200 lists them with every flag value, including `-1` and backslash
  paths (measured 2026-10-21). The `-1` workaround from 164078 lists nothing on 1.29, so a call
  with flags `-1` and no retry in the same function, in a mod that never uses `FindFileFlags.ALL`,
  is a 1.29 `RISK`. Counted as `-1`: the literal, a `const`/`static` the mod sets to `-1`, a method
  of the mod that returns `-1`, or a variable or parameter of the calling function that it sets to
  `-1` or that its callers pass `-1` into.
- **Known patterns:** `ChangeGameFocus` with no device argument (global input focus freezes
  menu input on 1.30; the per-device form vanilla uses is fine), `GetFluidCapacityScript`,
  `CreateInInventory` (not inside `OnDebugSpawn`, which only an admin's debug spawn runs), `Fill`.
- **Workbench classes** (`BREAK`): since 1.30.164200, `Workbench` and the other Workbench API classes
  (`WBModuleDef`, `ScriptEditor`, `WorkbenchPluginAttribute`, ...) are declared only under
  `#ifdef WORKBENCH`. Using one in a game script (`1_Core` to `5_Mission`) outside an
  `#ifdef WORKBENCH` block fails the module with "Can't find variable". Workbench plugin folders
  are skipped.
- **`vector.Cross()`** (`BREAK`): 1.30.164078 added it and 164200 removed it again, so `v.Cross(w)`
  no longer compiles. Not reported when the mod declares its own `Cross`.
- **Silent breakers** (compile, but 1.30 vanilla never calls them): overrides of `OnCEUpdate`
  (1.30 calls `OnCEIterate`), the old `GetNoiseReduction`/`GetNoiseReductionByWeather`, and
  `AddExplosionEffectForSurface` registrations.
- **Car lights** (`INFO`): overrides of `CreateFrontLight`/`CreateRearLight` are never called on
  1.30; the car still gets vanilla's default headlights, not its own brightness/range/colour.
- **Wrong version gates** (`RISK`): `#ifdef DAYZ_1_30` (off again on 1.31; use `#ifndef DAYZ_1_29`)
  and `BUILD_EXPERIMENTAL` (gone on 1.30 stable).
- **Version gates in `1_Core`** (`RISK`): `#ifdef`/`#ifndef DAYZ_1_xx` in a 1_Core script. The
  version defines aren't set yet when the Core module compiles (measured on 1.29), so the gate
  always takes the "not defined" branch. Use a runtime fallback there instead.
- **A variable named like another mod's class** (`BREAK`): a variable, parameter or field whose
  name is a class, enum or typedef another scanned mod declares, in a module that can see it
  (`1_Core` < `2_GameLib` < `3_Game` < `4_World` < `5_Mission`). With both mods loaded the module
  fails with "Variable name '...' already used as type name" (COT's kill-stats `c7` against
  CarPack's `class c7`). `RISK` when a module can't be told from the path. Workbench plugins are
  skipped.
- **Methods 1.30 made protected** (`RISK`), called from outside the class.
- **CfgMods script paths with backslashes**: 1.30 compiles none of that folder's scripts and logs
  nothing. Only `*ScriptModule` entries count; image sets with backslashes still load. The grade
  depends on what the skipped folder holds:
  - `BREAK` when other loaded code (this mod or another scanned one) uses a class, enum or typedef
    declared there, or a member a `modded class` there adds, through the class name
    (`ParticleList.x`): the module fails to compile. The finding names the file and the name.
  - `RISK` when the folder has code nothing else uses: it still compiles, but what it does is lost.
  - `INFO` when the folder has no scripts, or only empty classes (`class X : Y {};`), whose objects
    fall back to their config parent's script.
  A backslash path into *another* mod's folder (one not under any of this mod's PBO prefixes) is
  `RISK` when that PBO's scripts use `#ifdef`: mods list another mod's folder to pick up its
  `#define` for optional support, so on 1.30 that support can compile out. Without `#ifdef` it is
  `INFO`: the other mod loads its own scripts.
- **Methods 1.30 marks `[Obsolete]`** (they still compile). An override is `RISK` when 1.30 vanilla
  no longer calls that method (with that argument count), because the override never runs. A call
  is `RISK` when 1.30 left the method as a placeholder (empty, or returning a constant) and the mod
  doesn't override it, because the call does nothing. Otherwise both are `INFO`. A call that could
  equally be a current method of the same name in another class is `INFO` and names both, unless
  the variable it's called on has a declared type: then it names the class the call reaches, or
  isn't reported when that's the current one. A call that only fits a current overload isn't
  reported. Overloads are told apart by argument types where they're obvious: literals, and
  variables declared earlier in the same file. A vanilla call that also fits a current overload
  counts as calling that one. An override of an obsolete method is `INFO` when the same class also
  overrides the current overload, or the replacement the `[Obsolete]` message names
  (`IsVitalTruckBattery` → `NeedElectricitySourceDevice`).

**1.29** (`BREAK_129`, `RISK_129`), for builds that must still run on a 1.29 server:
- `modded class` of, or `extends`, a class that only exists from 1.30.
- Overrides of a method that only exists from 1.30, or written with its 1.30 signature.
- Calls of methods that only exist from 1.30: `BREAK_129` when the receiver's class is known (a
  variable's declared type, `Class.Method()`, or a getter with one return type, as in
  `GetGame().GetContentDLCService().GetDLCFromWorld()`), `RISK_129` otherwise. Uses of classes
  that only exist from 1.30 are `RISK_129`.

A method or field a mod declares in any of its own files counts as the mod's own, so calling it is
never mistaken for the vanilla name (overrides don't count: a call may still reach vanilla's).
Names that any scanned mod declares count as known for the 1.29 checks, so scan mods that depend
on each other together.

## Known limits

- The parser is regex and brace based. Defines other than `DAYZ_1_29`/`DAYZ_1_30` are not
  evaluated, so code under `#ifdef SERVER` or a mod's own define counts for both branches.
- Scrambled (obfuscated) PBOs parse, but hits there need a closer look. Both scanners read the
  PBOs in memory. `extract.py`, which writes the scripts to disk for reading, can't write a few of
  the decoy files in heavily scrambled PBOs (Windows refuses their paths), so a scan of its output
  can miss those.
- Config is not checked (for example, 1.30 needing a `<wheel>_Ruined` class for every wheel).

## Command line

Python 3, no packages to install. Run each script with `python -I`.

1. **Mod list**, `mods.tsv`: one line per mod, tab separated: `<number>\t<mod|serverMod>\t<@Folder>`.
   You can take it from a server's command line (`-mod=...;...`, split on `;`).
2. **Scan** the mods in a folder holding the `@Folder`s. The PBOs are read in memory:
   ```
   python -I python/scan130.py docs/vanilla.json --pbo mods.tsv <mods folder> scan.json
   ```
   `scan.json` lists, per mod, the hits by level with file and line, including the CfgMods script
   path check.

To read the code behind a hit, `extract.py` writes the scripts to a folder (keep it separate: they are
third-party code). `scan130.py` can also scan that folder, as it did before `--pbo`:
```
python -I python/extract.py mods.tsv <mods folder> modsrc
python -I python/scan130.py docs/vanilla.json modsrc scan.json mods.tsv <mods folder>
```

Also included: `python/deps.py` (mod-to-mod dependencies from `requiredAddons`), `python/modpaths.py`
(every backslash script path), and `python/hiddendeps.py` (dependencies a mod uses but doesn't
declare; needs the vanilla config files unpacked).

## The vanilla index

`docs/vanilla.json` holds the names and signatures of the vanilla classes, methods and fields (no
code) of up to three builds, by role: `stable` (the current stable build), `previous` (the build
stable is compared against) and `exp` (the open experimental build, when there is one newer than
stable). `versions` names the build in each role. A build is read from the `scripts.pbo` in that
install's `dta` folder (server or client), or an unpacked scripts folder.

## Updating for a new DayZ build

1. Update the data, by what changed:
   - **Stable hotfix** (same major.minor): `python -I python/vanilla.py set docs/vanilla.json stable <dta/scripts.pbo> <version>`
   - **New stable** (an Exp went stable): `python -I python/vanilla.py rotate docs/vanilla.json <stable dta/scripts.pbo> <version>`.
     The old stable becomes `previous`, and `exp` is cleared.
   - **New Exp**: `python -I python/vanilla.py set docs/vanilla.json exp <exp dta/scripts.pbo> <version>`.
     It refuses a build that isn't newer than stable.
   - **Exp closed, or only mirroring stable**: `python -I python/vanilla.py clear-exp docs/vanilla.json`
2. Run `python -I tools/rules.py`. It lists every hand-written check last verified on an older build
   than stable. Confirm each one on the new build and raise its `verified` in `tools/hand_rules.json`,
   or change it or drop it, in both scanners.
3. Scan the same mod set with the old and the new data, and run
   `python -I tools/before_after.py old.json new.json`. Every difference needs an explanation.
4. Run the parity check below, then `tools/stamp.py`, then push.

## Development

The web scanner in `docs/js` is a port of the Python scanner; the two must agree. `tools/parity.mjs`
runs the web code in Node over a mod list, and `tools/compare.py` checks the two reports hit for hit:
```
python -I python/scan130.py docs/vanilla.json --pbo mods.tsv <mods folder> py.json
node tools/parity.mjs docs/vanilla.json mods.tsv <mods folder> js.json
python -I tools/compare.py py.json js.json
```
Before pushing a change under `docs`, run `python -I tools/stamp.py`. It puts a new `?v=` on every
file the page loads, so a browser holding cached files from the last release can't mix them with
the new ones.

To try the page locally, serve `docs` (for example `python -m http.server -d docs`): browsers don't
run module scripts from `file://`.

## License

MIT. See `LICENSE`.

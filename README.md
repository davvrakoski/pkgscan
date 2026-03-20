# pkgscan

A lightweight AUR package security scanner that parses PKGBUILDs for malicious patterns before installation.

![demo](demo.gif)

## Features
- Simple static analysis of PKGBUILDs against known malicious patterns
- AUR metadata checks votes, age, maintainer, out-of-date flag
- Suspicion flag system for anomalous package behaviour
- Colored terminal output with danger scoring

## Dependencies
- `git`
- `base-devel`
- `curl`
- `cjson`

## Installation
```bash
git clone https://github.com/yourusername/pkgscan
cd pkgscan
make && sudo make install
```
Or Via AUR:

```bash
paru -S pkgscan
# or
yay -S pkgscan
```

## Usage
Scan a package directly:
```bash
pkgscan <package>
pkgscan pkg1 pkg2 pkg3
```
Or Use the makepkg hook:
```bash
pkgscan --hoke enable
(Restart Shell)
```
Then pkgscan will run automatically when using an AUR helper.

Help:
```bash
pkgscan --help
```

## How It Works
pkgscan clones the PKGBUILD from AUR and scores it against a keyword list with weighted danger values. Separately it fetches package metadata via the AUR RPC API and checks for flags like low vote counts, recent modifications after long inactivity, and out-of-date flags. The cloned directory is deleted after scanning regardless of outcome.

Keywords are defined in `keywords.h` and can be edited before recompiling.

## Danger Levels
| Level    | Score | Description                          |
|----------|-------|--------------------------------------|
| Low      | 0     | No suspicious patterns found         |
| Medium   | 1-15  | Some patterns detected               |
| High     | 16-35 | Suspicious patterns, review advised  |
| Critical | 35+   | Multiple serious patterns detected   |

## Limitations
- Static analysis only so obfuscated or encoded payloads may bypass detection
- Keyword list is open siource and can be studied by malicious package authors
- Metadata flags are heuristics, not guarantees
- Not a substitute for manual PKGBUILD review on high risk packages
- Sophisticated attacks are outside the scope of this tool

## Contributing
I'd appricate pull requests in order to help improve the code. To add or adjust detection patterns edit `keywords.h` and recompile.

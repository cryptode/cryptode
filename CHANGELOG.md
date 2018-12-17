
# Changelog

## [1.3.1] - 2018-12-17
### Changed

- Fixed issues after renamed the project
- Replace OpenVPN profiles for testing

## [1.3.0] - 2018-11-08
### Changed

- Renamed `rvc` to `cryptode`, `rvd` to `cryptoded`

## [1.2.3] - 2018-09-10
### Fixed

- Removed `default:all` notation from NOS options
- Set `RVD_USER_ID` while installing

## [1.2.2] - 2018-07-20
### Added

- Integrated `rvc` with `libnereon`

## [1.2.1] - 2018-07-09
### Changed

- Fixed issues when parsing per-VPN configuration by `libnereon`

## [1.2.0] - 2018-07-03
### Added

- Integrated `libnereon` for parsing configurations

# Changelog

## [1.1.2] - 2018-05-11
### Changed

- Set `user_id` in `rvd.json`

## [1.1.1] - 2018-02-01
### Added

- Added `rvd.systemd`

### Changed

- Changed RPM spec to use `rvd.systemd`
- Disabled UID in configuration for Linux

### Removed

- Removed `rvd.init` script

## [1.1.0] - 2018-01-30
### Added

### Changed

- Changed the JSON output format of `rvc status --json`

### Removed

## [1.0.4] - 2018-01-09
### Added

- Added ChangeLog
- Added `make-release` target into Makefille

### Changed

- Fixed README

### Removed

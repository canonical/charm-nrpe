# Development

## Setup

To make contributions to this charm, you'll need a working [development setup](https://juju.is/docs/sdk/dev-setup).

You can use the environments created by `tox` for development:

```shell
tox --notest -e unit
source .tox/unit/bin/activate
```

## Testing

This project uses `tox` and `make` for managing test environments. There are some pre-configured environments
that can be used for linting and formatting code when you're preparing contributions to the charm:

```shell
make black           # update your code according to black linting rules
make lint            # code style
make unittests       # unit tests
make functional      # functional tests
```

NOTE: this repository includes submodules.
It is important that these are checked out before building or testing the charm.
The `build` make target will init and update the submodules as a dependency,
or you can manually run `make submodules` or use the `git submodule` commands directly.

## Build the charm

Build the charm in this git repository using:

```shell
make build
```

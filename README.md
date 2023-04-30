# BSides Charm Fuzzing Training

## Cloning the Repository

This project uses git submodules. To clone the repository, use the
following command:

```shell
git clone --recurse-submodules --shallow-submodules
```

If you've already cloned the repository without recursing over the submodules,
you can run the following command to pull the submodules:

```shell
git submodule init
git submodule update --recursive
```

## The Laws of Fuzzing

1. If you fuzz something no one else has, you will find bugs.
1. Where there are parsers, there are bugs.

## FAQ

### I used the Docker container and found crashes, but after exiting the container I can't access them?

First, ensure that you mount the `output` volume using the `--volume` flag (for example, `--volume $(pwd)/output:/output`). This mounts the folder names `output` in the current directory to the root-level directory of the container. Anything written to that folder in the container will be written to the host's `output` folder as well. Second, the container is set to run as the `root` user (unless you've configured your Docker install differently, in which case it might be another user). This means that the output written by AFL will be owned by `root`. Presumably, you're not running your host as `root`. Recursively modify the owner of `output` to your user like so: `sudo chown --recursive $USER:$USER ./output`. You should now be able to access the files in `output`.

### The AFL screen has a lot of information. What does it all mean?

We cover a few of the options in the lecture, but you can find all of the information [here](https://aflplus.plus/docs/status_screen/).

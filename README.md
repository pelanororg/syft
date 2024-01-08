## See [here](https://github.com/anchore/syft/blob/main/README.md) for Syft's README

This repository is Pelanor's private fork of Syft - we slightly modify its CLI source code to export its `main` function so we can consume it in our Graviton Migration agent.

This enables us to dynamically link Syft into the agent's address space - we can then `chroot` into pods' filesystems and directly call the `main` function on them. This is a workaround for the following non-working alternatives:

1. Directly calling `syft` on pods' filesystems, i.e. `syft dir:/proc/<PID>/root`. This fails because the agent and the pod run from different mount namespaces, which causes Syft's directory traversal to breakdown - for instance, it will start traversing all *host* directories.

2. Calling `chroot` to change the root to the pods' filesystems, i.e. `chroot /proc/<PID>/root`, and then doing `syft dir:/`. This fails because `syft` needs to be installed *within* the pods' filesystems in order to work - we could consider copying `syft` into the filesystems, but many pods have readonly filesystems.